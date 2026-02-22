# CIS AWS Foundations Benchmark — Controls Reference

> Marcus Paula | IT Engineer — TikTok EMEA  
> Version: CIS AWS Foundations Benchmark v1.4 / v2.0  
> Status column reflects common enterprise baseline implementation

---

## Overview

The CIS AWS Foundations Benchmark provides prescriptive guidance for establishing a secure baseline on AWS. It covers Identity, Storage, Logging, Monitoring, and Networking.

**Benchmark Structure:**
- Section 1: Identity and Access Management
- Section 2: Storage (S3)
- Section 3: Logging
- Section 4: Monitoring
- Section 5: Networking

---

## Section 1 — Identity and Access Management

| Control | Description | Level | Verification Command |
|---------|-------------|-------|---------------------|
| 1.1 | Root MFA enabled | L1 | `aws iam get-account-summary \| jq '.SummaryMap.AccountMFAEnabled'` |
| 1.2 | Users without console access or with MFA | L1 | See `aws-iam-audit.py` |
| 1.3 | Unused credentials disabled (90 days) | L1 | Credential report |
| 1.4 | No active root access keys | L1 | `aws iam get-account-summary \| jq '.SummaryMap.AccountAccessKeysPresent'` |
| 1.5 | Password: require uppercase | L1 | `aws iam get-account-password-policy` |
| 1.6 | Password: require lowercase | L1 | `aws iam get-account-password-policy` |
| 1.7 | Password: require symbols | L1 | `aws iam get-account-password-policy` |
| 1.8 | Password: require numbers | L1 | `aws iam get-account-password-policy` |
| 1.9 | Password: min length 14 | L1 | `aws iam get-account-password-policy` |
| 1.10 | Password: expiry <= 90 days | L1 | `aws iam get-account-password-policy` |
| 1.11 | Password: reuse prevention >= 24 | L1 | `aws iam get-account-password-policy` |
| 1.12 | No root account access key | L1 | CIS 1.4 overlap |
| 1.13 | Access keys rotated within 90 days | L1 | Credential report |
| 1.14 | Active access keys only for active users | L1 | Credential report |
| 1.15 | IAM Access Analyzer enabled | L1 | `aws accessanalyzer list-analyzers` |
| 1.16 | No AdministratorAccess directly attached to user | L1 | `aws iam list-users` + list-attached |
| 1.17 | Support role exists | L1 | `aws iam list-roles \| grep support` |
| 1.18 | Instance profiles used (not access keys on EC2) | L2 | EC2 metadata check |
| 1.19 | Expired SSL/TLS certs removed from IAM | L1 | `aws iam list-server-certificates` |
| 1.20 | IAM Access Analyzer all active findings resolved | L2 | Access Analyzer console |
| 1.21 | SSO enabled | L2 | `aws sso-admin list-instances` |

### IAM Automation Checks

```bash
# CIS 1.1 — Root MFA
aws iam get-account-summary \
  --query 'SummaryMap.AccountMFAEnabled'

# CIS 1.4 — Root access keys (should be 0)
aws iam get-account-summary \
  --query 'SummaryMap.AccountAccessKeysPresent'

# CIS 1.15 — IAM Access Analyzer enabled
aws accessanalyzer list-analyzers \
  --query 'analyzers[?status==`ACTIVE`].name' \
  --output table

# CIS 1.19 — Expired SSL/TLS certificates
aws iam list-server-certificates \
  --query 'ServerCertificateMetadataList[?Expiration < `'"$(date --iso-8601=seconds)"'`].{Name:ServerCertificateName,Expires:Expiration}' \
  --output table

# CIS 1.3 / 1.13 / 1.14 — Generate credential report
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query 'Content' --output text | base64 -d > /tmp/cred-report.csv
echo "Columns: $(head -1 /tmp/cred-report.csv)"
```

---

## Section 2 — Storage

| Control | Description | Level | Automated Check |
|---------|-------------|-------|----------------|
| 2.1.1 | S3 bucket: no public access | L1 | `s3-security-audit.py` |
| 2.1.2 | S3: MFA Delete enabled | L1 | `aws s3api get-bucket-versioning` |
| 2.1.3 | S3: bucket policy denies HTTP | L1 | `aws s3api get-bucket-policy` |
| 2.1.4 | S3: access logging enabled | L1 | `aws s3api get-bucket-logging` |
| 2.1.5 | S3: Block Public Access (account) | L1 | `aws s3control get-public-access-block` |
| 2.2.1 | EBS volumes encrypted at rest | L1 | `aws ec2 describe-volumes` |
| 2.3.1 | RDS instances encrypted | L1 | `aws rds describe-db-instances` |

```bash
# CIS 2.2.1 — EBS encryption check
aws ec2 describe-volumes \
  --query 'Volumes[?Encrypted==`false`].{ID:VolumeId,State:State,Size:Size}' \
  --output table

# Check default EBS encryption per region
aws ec2 get-ebs-encryption-by-default \
  --query 'EbsEncryptionByDefault'

# Enable default EBS encryption
aws ec2 enable-ebs-encryption-by-default

# CIS 2.3.1 — RDS encryption
aws rds describe-db-instances \
  --query 'DBInstances[?StorageEncrypted==`false`].{ID:DBInstanceIdentifier,Class:DBInstanceClass,Engine:Engine}' \
  --output table
```

---

## Section 3 — Logging

| Control | Description | Level | Check |
|---------|-------------|-------|-------|
| 3.1 | CloudTrail enabled in all regions | L1 | `aws cloudtrail describe-trails` |
| 3.2 | CloudTrail log file validation | L1 | Trail config: `LogFileValidationEnabled` |
| 3.3 | CloudTrail S3 bucket not public | L1 | S3 public access check on logs bucket |
| 3.4 | CloudTrail S3 access logging | L2 | S3 logging on the CloudTrail bucket |
| 3.5 | CloudTrail integrated with CloudWatch Logs | L1 | `aws cloudtrail get-trail-status` |
| 3.6 | AWS Config enabled | L2 | `aws configservice describe-configuration-recorders` |
| 3.7 | CloudTrail S3 bucket access via CloudTrail | L1 | CloudTrail S3 data events |
| 3.8 | CloudTrail KMS encryption | L2 | Trail KMS key check |
| 3.9 | VPC flow logging | L2 | `aws ec2 describe-flow-logs` |
| 3.10 | Object-level logging for read events | L2 | CloudTrail data events |
| 3.11 | Object-level logging for write events | L2 | CloudTrail data events |

```bash
# CIS 3.1 — Multi-region trail exists
aws cloudtrail describe-trails \
  --query 'trailList[?IsMultiRegionTrail==`true`].{Name:Name,Bucket:S3BucketName,LogValidation:LogFileValidationEnabled}' \
  --output table

# CIS 3.2 — Log file validation enabled
aws cloudtrail describe-trails \
  --query 'trailList[?LogFileValidationEnabled==`false`].Name' \
  --output table

# CIS 3.6 — Config recorder status
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[].{Name:name,Recording:recording,LastStatus:lastStatus}' \
  --output table

# CIS 3.9 — VPC Flow Logs
aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text | tr '\t' '\n' | while read vpc; do
  count=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query 'length(FlowLogs)' --output text)
  echo "$vpc: $count flow log(s)"
done
```

---

## Section 4 — Monitoring (CloudWatch Alarms + Metric Filters)

Each alarm requires: CloudTrail → CloudWatch Logs → Metric Filter → Alarm → SNS.

| Control | Description | Filter Pattern |
|---------|-------------|----------------|
| 4.1 | Unauthorized API calls | `{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }` |
| 4.2 | Console logins without MFA | `{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed != "Yes" }` |
| 4.3 | Root account usage | `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }` |
| 4.4 | IAM policy changes | `{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=SetDefaultPolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }` |
| 4.5 | CloudTrail config changes | `{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }` |
| 4.6 | Console auth failures | `{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }` |
| 4.7 | Disable or delete CMKs | `{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }` |
| 4.8 | S3 bucket policy changes | `{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }` |
| 4.9 | Config changes | `{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder)) }` |
| 4.10 | Security Group changes | `{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }` |
| 4.11 | NACL changes | `{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }` |
| 4.12 | Network gateway changes | `{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }` |
| 4.13 | Route table changes | `{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }` |
| 4.14 | VPC changes | `{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }` |

### Deploy CIS 4.3 (root usage alarm)

```bash
LOG_GROUP="CloudTrail/DefaultLogGroup"
SNS_ARN="arn:aws:sns:eu-west-1:ACCOUNT:security-alerts"

# Create metric filter
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "RootAccountUsage" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations '[{
    "metricName": "RootAccountUsage",
    "metricNamespace": "CISBenchmark",
    "metricValue": "1",
    "defaultValue": 0
  }]'

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-4.3-RootAccountUsage" \
  --alarm-description "CIS 4.3: Root account activity detected" \
  --metric-name "RootAccountUsage" \
  --namespace "CISBenchmark" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_ARN" \
  --treat-missing-data notBreaching
```

---

## Section 5 — Networking

| Control | Description | Level | Check |
|---------|-------------|-------|-------|
| 5.1 | No NACL allows unrestricted ingress on SSH | L1 | `aws ec2 describe-network-acls` |
| 5.2 | No NACL allows unrestricted ingress on RDP | L1 | `aws ec2 describe-network-acls` |
| 5.3 | No Security Group allows unrestricted ingress on SSH | L1 | `aws ec2 describe-security-groups` |
| 5.4 | No Security Group allows unrestricted ingress on RDP | L1 | `aws ec2 describe-security-groups` |
| 5.5 | VPC default SG restricts all traffic | L2 | Default SG check |
| 5.6 | VPC peering least access routing | L2 | Route table review |

---

## CIS v2.0 Additional Controls (new since v1.4)

| Control | Description |
|---------|-------------|
| 1.21 | Ensure IAM users are managed centrally via identity federation or SSO |
| 2.1.1 | S3 buckets use SSE-KMS (updated) |
| 2.4.1 | Audit Manager enabled |
| 3.1 | CloudTrail enabled on all regions (multi-region) |
| 3.10 | S3 object-level logging for read events |
| 3.11 | S3 object-level logging for write events |

---

## Quick Compliance Score Check

```bash
#!/bin/bash
# Rough CIS compliance status check
echo "=== CIS AWS Foundations Benchmark — Quick Check ==="

echo -n "1.1 Root MFA: "
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text

echo -n "1.4 Root Access Keys: "
count=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text)
[ "$count" = "0" ] && echo "PASS (0 keys)" || echo "FAIL ($count key(s) exist)"

echo -n "1.15 Access Analyzer: "
count=$(aws accessanalyzer list-analyzers --query 'length(analyzers[?status==`ACTIVE`])' --output text)
[ "$count" -gt 0 ] && echo "PASS ($count analyzer(s))" || echo "FAIL (no active analyzer)"

echo -n "3.1 Multi-region CloudTrail: "
count=$(aws cloudtrail describe-trails --query 'length(trailList[?IsMultiRegionTrail==`true`])' --output text)
[ "$count" -gt 0 ] && echo "PASS ($count multi-region trail(s))" || echo "FAIL"

echo -n "3.6 Config Recorder: "
status=$(aws configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[0].recording' --output text 2>/dev/null)
[ "$status" = "True" ] && echo "PASS" || echo "FAIL or not configured"

echo -n "2.1.5 S3 Account-level Block Public Access: "
result=$(aws s3control get-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)
if echo "$result" | grep -q '"true"'; then
  echo "PARTIAL — check all four settings"
elif [ -z "$result" ]; then
  echo "FAIL — not configured"
else
  echo "$result"
fi
```

---

## References

- [CIS AWS Foundations Benchmark v1.4](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS AWS Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Hub CIS Standard](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- [NIST 800-53 AWS mapping](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search)
