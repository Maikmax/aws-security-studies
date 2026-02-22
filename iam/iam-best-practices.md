# IAM Best Practices — CIS + AWS Well-Architected

> Marcus Paula | IT Engineer — TikTok EMEA  
> Based on: CIS AWS Foundations Benchmark v1.4/2.0 · AWS Well-Architected Security Pillar

---

## 1. Root Account Hardening

The root account has unrestricted access to every AWS resource. Treat it as a break-glass account.

| Action | CIS Control | Priority |
|--------|-------------|----------|
| Enable MFA on root (hardware token preferred) | CIS 1.1 | CRITICAL |
| Delete all root access keys | CIS 1.4 | CRITICAL |
| Do not use root for day-to-day operations | CIS 1.0 | CRITICAL |
| Enable root login alerts via CloudWatch + SNS | CIS 1.7 (2.0) | HIGH |
| Store root credentials in offline vault | — | HIGH |

```bash
# Verify root MFA status
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'

# Check for root access keys (should return 0)
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'

# CloudWatch alarm for root login
aws cloudwatch put-metric-alarm \
  --alarm-name "RootAccountUsage" \
  --metric-name "RootAccountUsage" \
  --namespace "CloudTrailMetrics" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:REGION:ACCOUNT:security-alerts
```

---

## 2. Password Policy

```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --require-numbers \
  --require-symbols \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --hard-expiry
```

| Parameter | CIS Requirement | Rationale |
|-----------|----------------|-----------|
| Minimum length | >= 14 characters | Brute-force resistance |
| Complexity | Upper + lower + number + symbol | Entropy increase |
| Max age | <= 90 days | Limits exposure from leaked credentials |
| Reuse prevention | >= 24 passwords | Prevents cycling between known passwords |
| Hard expiry | True | Forces password reset, no console bypass |

---

## 3. Multi-Factor Authentication (MFA)

### 3.1 Enforce MFA for all console users

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyWithoutMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

Attach this as a Service Control Policy (SCP) at the AWS Organizations level to enforce it across all accounts.

```bash
# List users without MFA who have console access
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read user; do
  login=$(aws iam get-login-profile --user-name "$user" 2>/dev/null)
  mfa=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output text)
  if [ -n "$login" ] && [ -z "$mfa" ]; then
    echo "NO MFA: $user"
  fi
done
```

---

## 4. Access Key Management

### 4.1 Rotation policy

```bash
# Find access keys older than 90 days
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read user; do
  aws iam list-access-keys --user-name "$user" \
    --query "AccessKeyMetadata[?Status=='Active'].{User:'$user',Key:AccessKeyId,Created:CreateDate}" \
    --output table
done
```

### 4.2 Automated key rotation pattern

```python
import boto3
from datetime import datetime, timezone, timedelta

iam = boto3.client('iam')
ROTATION_DAYS = 90

users = iam.list_users()['Users']
for user in users:
    username = user['UserName']
    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    for key in keys:
        if key['Status'] != 'Active':
            continue
        age = (datetime.now(timezone.utc) - key['CreateDate']).days
        if age > ROTATION_DAYS:
            print(f"STALE KEY: {username} / {key['AccessKeyId']} ({age} days)")
            # Deactivate only — never delete without verification
            # iam.update_access_key(UserName=username, AccessKeyId=key['AccessKeyId'], Status='Inactive')
```

### 4.3 Prefer IAM roles over long-term keys

| Scenario | Preferred Approach |
|----------|--------------------|
| EC2 accessing S3 | EC2 Instance Profile |
| Lambda accessing DynamoDB | Lambda Execution Role |
| Cross-account access | Role with AssumeRole trust |
| CI/CD pipeline | OIDC federation (no long-term keys) |
| External vendor | Role with ExternalId condition |
| Human admin access | AWS SSO / Identity Center |

---

## 5. Principle of Least Privilege

### 5.1 Policy authoring

- Start with AWS managed policies for reference only
- Write customer-managed policies scoped to exact resources and actions
- Use policy variables where possible (`${aws:username}`, `${aws:userid}`)
- Test with IAM Policy Simulator before applying

### 5.2 Condition keys that reduce blast radius

```json
{
  "Condition": {
    "StringEquals": {
      "aws:RequestedRegion": ["eu-west-1", "eu-central-1"]
    },
    "IpAddress": {
      "aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]
    },
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    },
    "DateGreaterThan": {
      "aws:CurrentTime": "2025-01-01T00:00:00Z"
    }
  }
}
```

### 5.3 IAM Access Analyzer

```bash
# Create analyzer for current account
aws accessanalyzer create-analyzer \
  --analyzer-name prod-analyzer \
  --type ACCOUNT

# List findings (external access to your resources)
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:eu-west-1:ACCOUNT:analyzer/prod-analyzer \
  --filter '{"status": {"eq": ["ACTIVE"]}}' \
  --query 'findings[].{Resource:resource,Action:action,Principal:principal}' \
  --output table
```

---

## 6. IAM Roles Best Practices

### 6.1 Trust policy principles

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::TRUSTED_ACCOUNT_ID:role/specific-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "UNIQUE_EXTERNAL_ID"
        },
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

### 6.2 Service Control Policies (SCPs) for guardrails

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeaveOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "DenyDisableCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyRegionsOutsideEU",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "support:*",
        "sts:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:RequestedRegion": ["eu-*"]
        }
      }
    }
  ]
}
```

---

## 7. Monitoring IAM Events

### Key CloudTrail events to alert on

| Event | Severity | Rationale |
|-------|----------|-----------|
| `ConsoleLogin` with `additionalEventData.MFAUsed = No` | HIGH | MFA bypass |
| `CreateUser` | MEDIUM | New principal created |
| `AttachUserPolicy` with Admin ARN | CRITICAL | Privilege escalation |
| `DeleteTrail` / `StopLogging` | CRITICAL | Audit tampering |
| `AssumeRoleWithWebIdentity` from unknown OIDC | HIGH | Token abuse |
| `CreateAccessKey` | MEDIUM | New long-term credential |
| `PutUserPolicy` (inline policy) | HIGH | Inline policy abuse |

```bash
# Find all CreateUser events in last 7 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time $(date -d '7 days ago' --iso-8601=seconds) \
  --query 'Events[].{Time:EventTime,User:Username,Event:EventName}' \
  --output table
```

---

## 8. Unused Access Cleanup

```bash
# Generate credential report
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > creds.csv

# Key columns to review:
# - password_last_used
# - access_key_1_last_used_date
# - access_key_2_last_used_date
# - mfa_active

# List roles not used in 90 days (via Access Advisor)
aws iam list-roles --query 'Roles[].RoleName' --output text | tr '\t' '\n' | while read role; do
  last=$(aws iam get-role --role-name "$role" --query 'Role.RoleLastUsed.LastUsedDate' --output text 2>/dev/null)
  echo "$role: $last"
done
```

---

## References

- [CIS AWS Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
