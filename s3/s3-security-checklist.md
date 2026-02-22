# S3 Security Checklist

> Marcus Paula | IT Engineer — TikTok EMEA  
> Based on CIS AWS Foundations Benchmark + AWS Security Best Practices

---

## Quick Reference

| Control | Severity | CIS Ref | Command to Check |
|---------|----------|---------|-----------------|
| Block Public Access (account level) | CRITICAL | CIS 2.1.5 | `aws s3control get-public-access-block` |
| Block Public Access (bucket level) | HIGH | CIS 2.1.1 | `aws s3api get-public-access-block` |
| No public ACLs | CRITICAL | CIS 2.1.2 | `aws s3api get-bucket-acl` |
| Default encryption enabled | HIGH | CIS 2.1.1 | `aws s3api get-bucket-encryption` |
| Versioning enabled | MEDIUM | CIS 2.1.3 | `aws s3api get-bucket-versioning` |
| MFA Delete enabled | MEDIUM | CIS 2.1.3 | `aws s3api get-bucket-versioning` |
| Server access logging | MEDIUM | CIS 2.1.4 | `aws s3api get-bucket-logging` |
| SSL-only policy (deny HTTP) | MEDIUM | AWS Sec | `aws s3api get-bucket-policy` |
| Object Lock / WORM | LOW | Compliance | `aws s3api get-object-lock-configuration` |
| Cross-region replication | LOW | DR | `aws s3api get-bucket-replication` |

---

## 1. Block Public Access

### Account-level (applies to all buckets)

```bash
# Check current account-level block
aws s3control get-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text)

# Enable account-level block (covers all buckets)
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Bucket-level

```bash
BUCKET="my-bucket-name"

aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Scan all buckets for public access issues

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | while read bucket; do
  result=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
  if [ -z "$result" ]; then
    echo "NO BLOCK CONFIG: $bucket"
  else
    blocked=$(echo "$result" | python3 -c "
import json, sys
c = json.load(sys.stdin)['PublicAccessBlockConfiguration']
print('OK' if all(c.values()) else 'PARTIAL: ' + str(c))
")
    echo "$blocked: $bucket"
  fi
done
```

---

## 2. Encryption

### Set default encryption — SSE-KMS with CMK (recommended for sensitive data)

```bash
KMS_KEY_ID="arn:aws:kms:eu-west-1:ACCOUNT:key/KEY_ID"

aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "'"$KMS_KEY_ID"'"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

### Set default encryption — SSE-S3 (minimum baseline)

```bash
aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

### Encryption decision matrix

| Data Classification | Recommended Encryption | Key Management |
|--------------------|------------------------|----------------|
| Public/Static assets | SSE-S3 (AES256) | AWS-managed |
| Internal / PII | SSE-KMS (CMK) | Customer-managed |
| Regulated (GDPR, PCI) | SSE-KMS (CMK) | Customer-managed + key rotation |
| WORM / Compliance logs | SSE-KMS + Object Lock | Customer-managed |

---

## 3. Versioning and MFA Delete

```bash
# Enable versioning
aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

# Enable MFA Delete (requires root account + MFA device serial + current code)
# WARNING: this can only be done as root and cannot be reversed without root + MFA
aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::ACCOUNT:mfa/root-account-mfa-device MFA_CODE"

# List object versions (useful for recovery)
aws s3api list-object-versions \
  --bucket "$BUCKET" \
  --query 'DeleteMarkers[].{Key:Key,Date:LastModified}' \
  --output table
```

---

## 4. Server Access Logging

```bash
# First, create a dedicated logging bucket
LOG_BUCKET="s3-access-logs-$(aws sts get-caller-identity --query Account --output text)"

aws s3api create-bucket \
  --bucket "$LOG_BUCKET" \
  --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1

# Grant log delivery write access to logging bucket
aws s3api put-bucket-acl \
  --bucket "$LOG_BUCKET" \
  --grant-write URI=http://acs.amazonaws.com/groups/s3-service/Amazon-S3-Storage \
  --grant-read-acp URI=http://acs.amazonaws.com/groups/s3-service/Amazon-S3-Storage

# Enable logging on the target bucket
aws s3api put-bucket-logging \
  --bucket "$BUCKET" \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "'"$LOG_BUCKET"'",
      "TargetPrefix": "'"$BUCKET"'/"
    }
  }'
```

---

## 5. Enforce SSL-Only Access

Add this statement to every bucket policy (create one if none exists):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyHTTP",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::BUCKET_NAME",
        "arn:aws:s3:::BUCKET_NAME/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

```bash
# Apply SSL enforcement policy
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

aws s3api put-bucket-policy \
  --bucket "$BUCKET" \
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyHTTP",
      "Effect":"Deny",
      "Principal":"*",
      "Action":"s3:*",
      "Resource":["arn:aws:s3:::'"$BUCKET"'","arn:aws:s3:::'"$BUCKET"'/*"],
      "Condition":{"Bool":{"aws:SecureTransport":"false"}}
    }]
  }'
```

---

## 6. Lifecycle Policies (Cost + Compliance)

```bash
# Transition to IA after 30 days, Glacier after 90, expire after 365
aws s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET" \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "archive-and-expire",
      "Status": "Enabled",
      "Filter": {"Prefix": "logs/"},
      "Transitions": [
        {"Days": 30, "StorageClass": "STANDARD_IA"},
        {"Days": 90, "StorageClass": "GLACIER"}
      ],
      "Expiration": {"Days": 365},
      "NoncurrentVersionTransitions": [
        {"NoncurrentDays": 7, "StorageClass": "STANDARD_IA"}
      ],
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }]
  }'
```

---

## 7. S3 Security Hub Standards Coverage

| Security Hub Finding | S3 Control | Auto-Remediation |
|---------------------|------------|-----------------|
| S3.1 — Block Public Access (account) | `s3control put-public-access-block` | Config Rule: `s3-account-level-public-access-blocks` |
| S3.2 — Block Public Access (bucket) | `s3api put-public-access-block` | Config Rule: `s3-bucket-public-access-prohibited` |
| S3.3 — MFA Delete | Manual (root only) | No |
| S3.4 — S3 replication encrypted | KMS encryption on replica | Config Rule |
| S3.5 — SSL requests only | Bucket policy | Config Rule: `s3-bucket-ssl-requests-only` |
| S3.6 — Grant read access to S3 group | ACL review | Config Rule |
| S3.8 — Access logging | `s3api put-bucket-logging` | Config Rule: `s3-bucket-logging-enabled` |
| S3.9 — Object-level logging (CloudTrail) | CloudTrail data events | Config Rule |
| S3.11 — Event notifications | `s3api put-bucket-notification-configuration` | No |
| S3.13 — Lifecycle policy | `s3api put-bucket-lifecycle-configuration` | No |

---

## 8. Full Bucket Hardening Script

```bash
#!/bin/bash
# Harden a single S3 bucket — run after creating any new bucket
# Usage: ./harden-bucket.sh BUCKET_NAME [KMS_KEY_ARN]

BUCKET="${1:?Usage: $0 BUCKET_NAME [KMS_KEY_ARN]}"
KMS_KEY="${2:-}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

echo "[1] Block public access..."
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "[2] Enable versioning..."
aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

echo "[3] Enable encryption..."
if [ -n "$KMS_KEY" ]; then
  aws s3api put-bucket-encryption --bucket "$BUCKET" \
    --server-side-encryption-configuration \
      '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"'"$KMS_KEY"'"},"BucketKeyEnabled":true}]}'
else
  aws s3api put-bucket-encryption --bucket "$BUCKET" \
    --server-side-encryption-configuration \
      '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
fi

echo "[4] Enforce SSL-only..."
aws s3api put-bucket-policy --bucket "$BUCKET" --policy '{
  "Version":"2012-10-17",
  "Statement":[{"Sid":"DenyHTTP","Effect":"Deny","Principal":"*","Action":"s3:*",
    "Resource":["arn:aws:s3:::'"$BUCKET"'","arn:aws:s3:::'"$BUCKET"'/*"],
    "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'

echo "[5] Done. Run s3-security-audit.py to verify."
```

---

## References

- [CIS AWS Foundations Benchmark — S3 Section](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Security Hub S3 Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html)
