# AWS Security Services — Quick Reference

> Marcus Paula | IT Engineer — TikTok EMEA  
> 14x AWS Certifications | Summary of core security services

---

## Service Overview Matrix

| Service | Category | Purpose | Cost Model |
|---------|----------|---------|------------|
| IAM | Identity | Users, roles, policies | Free |
| IAM Access Analyzer | Identity | External access detection | Free (basic) |
| AWS SSO / Identity Center | Identity | Centralized SSO | Free |
| CloudTrail | Logging | API activity recording | Per event, data events extra |
| CloudWatch | Monitoring | Metrics, logs, alarms | Per metric/log/alarm |
| Config | Compliance | Resource config recording + rules | Per rule evaluation |
| Security Hub | CSPM | Centralized findings + standards | Per finding |
| GuardDuty | Threat Detection | ML-based anomaly + threat detection | Per GB analyzed |
| Inspector | Vuln Assessment | EC2/ECR/Lambda CVE scanning | Per assessment |
| Macie | Data Security | S3 PII and sensitive data discovery | Per GB scanned |
| KMS | Encryption | Key management and cryptography | Per key/API call |
| Secrets Manager | Secrets | Store and rotate credentials | Per secret/API call |
| WAF | Network | L7 web application firewall | Per rule/request |
| Shield | Network | DDoS protection | Free (Standard) / $3k/mo (Advanced) |
| Network Firewall | Network | VPC-level stateful firewall | Per AZ + traffic |
| Certificate Manager | PKI | TLS certificates | Free (public certs) |
| Detective | Forensics | Graph-based IR investigation | Per GB ingested |
| Artifact | Compliance | AWS compliance reports | Free |

---

## Amazon GuardDuty

### What it detects

GuardDuty analyzes: CloudTrail management events, CloudTrail S3 data events, VPC Flow Logs, DNS query logs, EKS audit logs, RDS login events.

| Threat Category | Example Findings |
|----------------|-----------------|
| **Reconnaissance** | `Recon:IAMUser/UserPermissions` — user enumerating permissions |
| **Instance Compromise** | `CryptoCurrency:EC2/BitcoinTool.B` — cryptocurrency mining |
| **Account Compromise** | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` — login from unusual location |
| **Data Exfiltration** | `Exfiltration:S3/MaliciousIPCaller` — S3 access from threat-listed IP |
| **Persistence** | `Persistence:IAMUser/NetworkPermissions` — creating new network access |
| **Privilege Escalation** | `PrivilegeEscalation:Lambda/AnomalousBehavior` — Lambda acquiring higher privileges |
| **Defense Evasion** | `Stealth:IAMUser/CloudTrailLoggingDisabled` — CloudTrail stopped |

```bash
# Enable with all features
DETECTOR_ID=$(aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --features '[
    {"Name":"S3_DATA_EVENTS","Status":"ENABLED"},
    {"Name":"EKS_AUDIT_LOGS","Status":"ENABLED"},
    {"Name":"EBS_MALWARE_PROTECTION","Status":"ENABLED"},
    {"Name":"RDS_LOGIN_EVENTS","Status":"ENABLED"},
    {"Name":"LAMBDA_NETWORK_LOGS","Status":"ENABLED"}
  ]' \
  --query 'DetectorId' --output text)

echo "Detector ID: $DETECTOR_ID"
```

---

## Amazon Inspector

### Version comparison

| Feature | Inspector Classic (v1) | Inspector v2 |
|---------|----------------------|-------------|
| EC2 scanning | Agent-based | Agentless (SSM) |
| ECR scanning | No | Yes (on push) |
| Lambda scanning | No | Yes |
| CVE source | NVD | NVD + vendor advisories |
| Integration | Security Hub optional | Security Hub native |
| Network reachability | Yes | Yes |

### Inspector v2 — key commands

```bash
# Enable Inspector v2
aws inspector2 enable \
  --resource-types EC2 ECR LAMBDA LAMBDA_CODE

# Get CVSS 9.0+ vulnerabilities
aws inspector2 list-findings \
  --filter-criteria '{
    "inspectorScoreRange": [{"lowerInclusive": 9.0, "upperInclusive": 10.0}],
    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
  }' \
  --query 'findings[].{CVE:packageVulnerabilityDetails.vulnerabilityId,Score:inspectorScore,Resource:resources[0].id,Package:packageVulnerabilityDetails.vulnerablePackages[0].name}' \
  --output table

# Check coverage (which resources are scanned)
aws inspector2 list-coverage \
  --filter-criteria '{"scanStatusCode":[{"comparison":"EQUALS","value":"INACTIVE"}]}' \
  --query 'coveredResources[].{Resource:resourceId,Reason:scanStatus.reason}' \
  --output table
```

---

## Amazon Macie

### Data identifiers — what Macie detects

| Category | Examples |
|----------|---------|
| PII | Name, SSN, passport, driving license, date of birth |
| Financial | Credit card numbers, IBAN, SWIFT codes |
| Credentials | API keys, AWS credentials, passwords in plaintext |
| Healthcare | NHS number, health insurance ID |
| Legal | Legal case numbers |
| Network | IP addresses, MAC addresses |

```bash
# Enable Macie
aws macie2 enable-macie

# Create a sensitive data discovery job
aws macie2 create-classification-job \
  --job-type SCHEDULED \
  --schedule-frequency '{"dailySchedule": {}}' \
  --name "daily-sensitive-data-scan" \
  --s3-job-definition '{
    "bucketDefinitions": [{"accountId": "ACCOUNT", "buckets": ["my-sensitive-bucket"]}],
    "scoping": {"includes": {"and": []}}
  }' \
  --sampling-percentage 100

# Get unencrypted buckets with sensitive data
aws macie2 list-findings \
  --filter-criteria '{
    "findingType": [{"comparison": "EQ", "values": ["SensitiveData:S3Object/Credentials"]}]
  }' \
  --query 'findingIds' --output text
```

---

## AWS KMS

### Key Types

| Key Type | Created By | Rotation | Use Case |
|----------|-----------|----------|---------|
| AWS managed | AWS | Auto (yearly) | Default service encryption |
| Customer managed (CMK) | You | Optional (yearly) | Custom key policy, auditing |
| Data key | KMS generates | N/A | Envelope encryption |
| Asymmetric key | You | No | RSA/ECC signing or encryption |
| Multi-region key | You | Optional | Cross-region replication |
| External key material | You (import) | No | BYOK compliance |

### Envelope encryption pattern

```
1. Call KMS GenerateDataKey → returns (plaintext DK + encrypted DK)
2. Use plaintext DK to encrypt your data locally
3. Store encrypted DK alongside encrypted data
4. Delete plaintext DK from memory
5. To decrypt: call KMS Decrypt(encrypted DK) → plaintext DK → decrypt data
```

```python
import boto3, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

kms = boto3.client('kms')
KEY_ID = 'arn:aws:kms:eu-west-1:ACCOUNT:key/KEY_ID'

# Encrypt
response = kms.generate_data_key(KeyId=KEY_ID, KeySpec='AES_256')
plaintext_key = response['Plaintext']
encrypted_key = response['CiphertextBlob']

nonce = os.urandom(12)
aesgcm = AESGCM(plaintext_key)
ciphertext = aesgcm.encrypt(nonce, b"sensitive data", None)

# Store: encrypted_key + nonce + ciphertext
# Clear plaintext key from memory
del plaintext_key

# Decrypt
dk_response = kms.decrypt(CiphertextBlob=encrypted_key)
dk = dk_response['Plaintext']
aesgcm = AESGCM(dk)
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
```

### Key policy — restrict to specific roles only

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable Root Account",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow Lambda decrypt only",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/lambda-role"},
      "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "lambda.eu-west-1.amazonaws.com"
        }
      }
    }
  ]
}
```

---

## AWS Secrets Manager

### Storing and rotating secrets

```bash
# Store a secret
aws secretsmanager create-secret \
  --name "prod/myapp/db-password" \
  --secret-string '{"username":"admin","password":"REPLACE_WITH_REAL"}' \
  --kms-key-id arn:aws:kms:eu-west-1:ACCOUNT:key/KEY_ID

# Retrieve a secret (returns the JSON)
aws secretsmanager get-secret-value \
  --secret-id "prod/myapp/db-password" \
  --query 'SecretString' \
  --output text | python3 -c "import json,sys; print(json.load(sys.stdin)['password'])"

# Enable automatic rotation (requires rotation Lambda)
aws secretsmanager rotate-secret \
  --secret-id "prod/myapp/db-password" \
  --rotation-rules '{"AutomaticallyAfterDays": 30}'

# List secrets expiring in next 7 days
aws secretsmanager list-secrets \
  --filter Key=tag-key,Values=Environment \
  --query 'SecretList[?NextRotationDate < `'"$(date -d '+7 days' --iso-8601=seconds)"'`].{Name:Name,Next:NextRotationDate}' \
  --output table
```

### Secrets Manager vs SSM Parameter Store

| Feature | Secrets Manager | SSM Parameter Store |
|---------|----------------|---------------------|
| Automatic rotation | Yes (native Lambda) | No (manual Lambda needed) |
| Cross-account | Yes | Limited |
| Cost | $0.40/secret/month | Free (standard), $0.05/advanced |
| Size limit | 64KB | 4KB (standard), 8KB (advanced) |
| Audit trail | CloudTrail | CloudTrail |
| Hierarchy | Limited | Yes (paths: /app/env/key) |
| Use case | Credentials, API keys | Config values, feature flags |

---

## AWS Config

Config continuously records resource configurations and evaluates compliance rules.

```bash
# Check Config recorder status
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[].{Name:name,Recording:recording,LastStatus:lastStatus}' \
  --output table

# List non-compliant resources
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name restricted-ssh \
  --compliance-types NON_COMPLIANT \
  --query 'EvaluationResults[].{Resource:EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,Type:EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType}' \
  --output table

# List all non-compliant rules
aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT \
  --query 'ComplianceByConfigRules[].ConfigRuleName' \
  --output table
```

### Key Config managed rules

| Rule | What it checks |
|------|---------------|
| `restricted-ssh` | No SG allows 0.0.0.0/0:22 |
| `restricted-common-ports` | No SG allows 0.0.0.0/0 on 22, 3389, 1433, 3306, etc. |
| `s3-bucket-public-access-prohibited` | S3 Block Public Access enabled |
| `s3-bucket-ssl-requests-only` | S3 policy enforces HTTPS |
| `iam-root-access-key-check` | Root has no active access keys |
| `mfa-enabled-for-iam-console-access` | All console users have MFA |
| `access-keys-rotated` | Keys rotated within 90 days |
| `cloudtrail-enabled` | CloudTrail is enabled |
| `encrypted-volumes` | EBS volumes are encrypted |
| `rds-storage-encrypted` | RDS storage is encrypted |
| `guardduty-enabled-centralized` | GuardDuty is enabled |
| `vpc-flow-logs-enabled` | VPC Flow Logs are enabled |
| `kms-cmk-not-scheduled-for-deletion` | No CMKs pending deletion |

---

## AWS Artifact

Artifact provides on-demand access to AWS compliance reports and agreements.

| Document Type | Examples |
|--------------|---------|
| Audit reports | SOC 1, SOC 2, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS |
| Certifications | FedRAMP, IRAP, C5, ENS |
| Agreements | BAA (HIPAA), NDA, GDPR DPA |

```bash
# List available reports
aws artifact list-reports \
  --query 'reports[].{Name:name,Category:category,Status:statusMessage}' \
  --output table

# Get a specific report download URL
aws artifact get-report-metadata \
  --report-id REPORT_ID
```

Use Artifact reports as evidence for:
- Internal audits
- Customer due diligence
- Regulatory assessments (PCI QSA, ISO auditor)

---

## References

- [AWS Security Services Overview](https://aws.amazon.com/products/security/)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Inspector v2 Coverage](https://docs.aws.amazon.com/inspector/latest/user/supported-os.html)
- [KMS Key Concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
