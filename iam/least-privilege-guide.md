# Least Privilege in AWS — Practical Implementation Guide

> Marcus Paula | IT Engineer — TikTok EMEA  
> Applied in enterprise environments: 5,000+ devices · Dublin · Madrid · Milan

---

## What Least Privilege Means in Practice

Least privilege means a principal (user, role, service) has exactly the permissions needed to do its job — no more. In AWS this translates to:

1. **Specific actions** — `s3:GetObject` instead of `s3:*`
2. **Specific resources** — `arn:aws:s3:::my-bucket/*` instead of `*`
3. **Conditions** — restrict by IP, MFA, time, region
4. **Time-bound access** — temporary credentials via STS where possible
5. **Regular review** — remove unused permissions, rotate credentials

---

## Phase 1: Discovery — What Permissions Are Actually Used?

Before restricting anything, find out what is actually being called.

### IAM Access Advisor

```bash
# Get service last accessed data for a user
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::ACCOUNT:user/USERNAME

# Wait and fetch the report (job-id from above)
aws iam get-service-last-accessed-details \
  --job-id JOB_ID \
  --query 'ServicesLastAccessed[?TotalAuthenticatedEntities>`0`].{Service:ServiceName,LastAccess:LastAuthenticated}' \
  --output table
```

### CloudTrail — Extract actual API calls for a role

```bash
# What APIs did this role call in the last 30 days?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=ROLE_NAME \
  --start-time $(date -d '30 days ago' --iso-8601=seconds) \
  --query 'Events[].{Event:EventName,Service:EventSource,Time:EventTime}' \
  --output text | sort | uniq -c | sort -rn
```

### IAM Access Analyzer — Unused access findings

```bash
# Enable unused access analyzer (checks last 90 days of CloudTrail)
aws accessanalyzer create-analyzer \
  --analyzer-name unused-access-analyzer \
  --type ACCOUNT \
  --configuration '{"unusedAccess": {"unusedAccessAge": 90}}'

# Retrieve unused permissions findings
aws accessanalyzer list-findings-v2 \
  --analyzer-arn arn:aws:access-analyzer:eu-west-1:ACCOUNT:analyzer/unused-access-analyzer \
  --filter '{"findingType": {"eq": ["UnusedPermission"]}}' \
  --output table
```

---

## Phase 2: Policy Construction

### 2.1 Template: Developer role (S3 read + ECR push to specific repo)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadProjectBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::project-assets-prod",
        "arn:aws:s3:::project-assets-prod/*"
      ]
    },
    {
      "Sid": "ECRPushSpecificRepo",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ],
      "Resource": "arn:aws:ecr:eu-west-1:ACCOUNT:repository/myapp-repo"
    },
    {
      "Sid": "ECRAuthToken",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    }
  ]
}
```

### 2.2 Template: Lambda execution role (read SSM + write DynamoDB table)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SSMReadConfig",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters"
      ],
      "Resource": "arn:aws:ssm:eu-west-1:ACCOUNT:parameter/myapp/*"
    },
    {
      "Sid": "DynamoDBWriteTable",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:GetItem"
      ],
      "Resource": "arn:aws:dynamodb:eu-west-1:ACCOUNT:table/events-table"
    },
    {
      "Sid": "KMSDecrypt",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:eu-west-1:ACCOUNT:key/KEY_ID",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "dynamodb.eu-west-1.amazonaws.com"
        }
      }
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:eu-west-1:ACCOUNT:log-group:/aws/lambda/myapp-*"
    }
  ]
}
```

### 2.3 Template: Read-only security auditor

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityAuditReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:Generate*",
        "cloudtrail:Get*",
        "cloudtrail:Describe*",
        "cloudtrail:List*",
        "config:Get*",
        "config:Describe*",
        "config:List*",
        "securityhub:Get*",
        "securityhub:List*",
        "securityhub:Describe*",
        "guardduty:Get*",
        "guardduty:List*",
        "accessanalyzer:Get*",
        "accessanalyzer:List*",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "ec2:Describe*",
        "kms:Describe*",
        "kms:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Phase 3: Permission Boundaries

Permission boundaries set the maximum permissions a principal can ever have, regardless of what policies are attached. Useful when delegating IAM management to teams.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowServiceAccess",
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "lambda:*",
        "dynamodb:*",
        "logs:*",
        "cloudwatch:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyIAMEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePermissionsBoundary",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyLeavingBoundedRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:RequestedRegion": ["eu-west-1", "eu-central-1"]
        }
      }
    }
  ]
}
```

Apply the boundary when creating a role:

```bash
aws iam create-role \
  --role-name dev-team-role \
  --assume-role-policy-document file://trust-policy.json \
  --permissions-boundary arn:aws:iam::ACCOUNT:policy/DevTeamBoundary
```

---

## Phase 4: Privilege Escalation Prevention

### Common escalation paths to block

| Attack Path | API Calls Needed | Mitigation |
|-------------|------------------|------------|
| Attach admin policy to self | `iam:AttachUserPolicy` | Deny on own ARN |
| Create new admin user | `iam:CreateUser` + `iam:AttachUserPolicy` | SCP deny |
| Modify role trust policy | `iam:UpdateAssumeRolePolicy` | Deny or MFA condition |
| Pass role to EC2 | `iam:PassRole` (unrestricted) | Scope to specific roles |
| Create Lambda with privileged role | `iam:PassRole` + `lambda:CreateFunction` | Scope PassRole |
| Create policy version | `iam:CreatePolicyVersion` | Deny for managed policies |

### PassRole — the most underrated permission

```json
{
  "Sid": "PassRoleScopedOnly",
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::ACCOUNT:role/allowed-lambda-role",
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "lambda.amazonaws.com"
    }
  }
}
```

Never grant `iam:PassRole` on `Resource: "*"` without a service condition.

---

## Phase 5: Regular Review Cadence

| Frequency | Task |
|-----------|------|
| Weekly | Review IAM Access Analyzer findings |
| Monthly | Run credential report — check last-used dates |
| Quarterly | Review role permissions against Access Advisor |
| Quarterly | Validate permission boundaries still apply |
| On offboarding | Immediately revoke console access + deactivate keys |
| On incident | Rotate all credentials in affected scope |

```bash
# Monthly: generate and download credential report
aws iam generate-credential-report && sleep 5
aws iam get-credential-report \
  --query 'Content' \
  --output text | base64 -d > credential-report-$(date +%Y%m).csv

# Review: users with password but no MFA
awk -F',' 'NR>1 && $4=="true" && $8=="false" {print $1, $5}' credential-report-$(date +%Y%m).csv

# Review: access keys not used in 90 days
awk -F',' 'NR>1 {
  split($11, d, "T")
  print $1, d[1], $10
}' credential-report-$(date +%Y%m).csv | awk '{
  cmd = "date -d \"" $2 "\" +%s 2>/dev/null"
  cmd | getline ts; close(cmd)
  "date +%s" | getline now; close("date +%s")
  if ((now - ts) > 7776000) print "STALE:", $0
}'
```

---

## References

- [IAM Policy Simulator](https://policysim.aws.amazon.com/)
- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Privilege Escalation in AWS — Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Permission Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
