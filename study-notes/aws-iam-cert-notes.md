# AWS IAM — Certification Study Notes

> Marcus Paula | IT Engineer — TikTok EMEA  
> 14x AWS Certifications — IAM-focused notes from hands-on practice  
> Covers: IAM fundamentals, STS, federation, exam-relevant gotchas

---

## IAM Core Concepts

### Principal Types

| Principal | Description | Authenticated By |
|-----------|-------------|-----------------|
| IAM User | Permanent identity in an account | Username/password or access keys |
| IAM Role | Temporary identity assumed by someone | STS AssumeRole |
| IAM Group | Collection of users — not a principal itself | N/A |
| AWS Service | EC2, Lambda, etc. acting on your behalf | Service trust policy |
| Federated User | External IdP identity mapped to a role | SAML 2.0, OIDC, or Cognito |
| Anonymous | No authentication | Public S3, public API |

Key point: **Groups are not principals** — you cannot grant a group permission to assume a role or reference a group in a trust policy.

---

## Policy Evaluation Logic

AWS evaluates policies in this order (stop at first explicit Deny):

```
1. Explicit DENY in any policy → DENY (stops immediately)
2. Service Control Policy (SCP) — allow?
3. Resource-based policy — allow? (e.g., S3 bucket policy)
4. Identity-based policy — allow?
5. Permission boundary — allow?
6. Session policy (for role sessions) — allow?
If none explicitly allow → implicit DENY
```

### Cross-account policy evaluation

For cross-account access (e.g., Role A in Account A accesses S3 in Account B):
- **Both** accounts must allow the action:
  - Identity-based policy in Account A must allow `s3:GetObject`
  - Resource-based policy in Account B must allow Account A's principal
- If only one allows, access is denied

---

## STS and Temporary Credentials

| STS API | Use Case | Max Duration |
|---------|----------|-------------|
| `AssumeRole` | Cross-account or switching roles | 1h–12h (role setting) |
| `AssumeRoleWithSAML` | SAML 2.0 federation | 1h–12h |
| `AssumeRoleWithWebIdentity` | OIDC federation (Cognito, GitHub Actions) | 1h |
| `GetFederationToken` | Older: federated user with arbitrary policy | 15min–36h |
| `GetSessionToken` | MFA authentication or root to temp creds | 15min–36h |

### AssumeRole with MFA condition

```bash
# Assume a role and provide MFA token
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/admin-role \
  --role-session-name my-session \
  --serial-number arn:aws:iam::ACCOUNT:mfa/myuser \
  --token-code 123456

# Set temp credentials in environment
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

---

## Federation

### SAML 2.0 Federation

```
User → Corporate IdP (ADFS/Okta) → SAML assertion → AWS STS AssumeRoleWithSAML → AWS Console/API
```

Requirements:
1. SAML IdP metadata uploaded to AWS (`aws iam create-saml-provider`)
2. IAM role with trust policy allowing `saml-provider:SAML_PROVIDER_ARN`
3. SAML assertion contains role ARN and provider ARN as attributes

### OIDC Federation (GitHub Actions example)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:MY_ORG/MY_REPO:*"
      }
    }
  }]
}
```

This eliminates long-term credentials in CI/CD pipelines.

---

## IAM Policy Types — Summary

| Policy Type | Attached To | Can Deny | Cross-Account |
|-------------|-------------|----------|---------------|
| Identity-based | User/Role/Group | Yes | No (own account only) |
| Resource-based | S3, KMS, SQS, etc. | Yes | Yes |
| Service Control Policy | AWS Org OU/Account | No (only Allow/Deny boundaries) | Account-wide |
| Permission Boundary | User or Role | No (limits max permissions) | No |
| Session Policy | STS session | No (limits max session permissions) | No |
| ACL | S3, VPC | Deny in NACLs | Yes |

---

## Managed vs Inline Policies

| Feature | Managed Policy | Inline Policy |
|---------|---------------|---------------|
| Reusable | Yes | No (1:1 relationship) |
| Versioning | Up to 5 versions | No versioning |
| Visibility | Listed separately | Hidden inside entity |
| AWS managed | Yes (~800 policies) | No |
| Drift detection | Easier | Harder |
| Best practice | Preferred for most | Emergency/specific cases |

---

## IAM Roles for EC2 — Instance Profiles

```bash
# Create role with trust policy for EC2
aws iam create-role \
  --role-name MyEC2Role \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"Service":"ec2.amazonaws.com"},
      "Action":"sts:AssumeRole"
    }]
  }'

# Attach policy to role
aws iam attach-role-policy \
  --role-name MyEC2Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Create instance profile and add role
aws iam create-instance-profile --instance-profile-name MyEC2Profile
aws iam add-role-to-instance-profile --instance-profile-name MyEC2Profile --role-name MyEC2Role

# Attach profile to running instance
aws ec2 associate-iam-instance-profile \
  --instance-id i-xxxxxxxxxxxxxxxxx \
  --iam-instance-profile Name=MyEC2Profile

# From the EC2 instance: fetch temp credentials via IMDS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
```

---

## Commonly Confused Concepts

### `iam:PassRole` vs `sts:AssumeRole`

- `sts:AssumeRole`: You call STS to assume a role and get temporary credentials
- `iam:PassRole`: You authorize an AWS service (EC2, Lambda) to use a role on your behalf

Without `iam:PassRole`, a user cannot launch an EC2 instance with a specific role — even if they can call `sts:AssumeRole`.

### Principal: `*` vs `Principal: {"AWS": "*"}`

- `"Principal": "*"` — any principal, including unauthenticated (S3 public access)
- `"Principal": {"AWS": "*"}` — any authenticated AWS principal

Both are public in resource-based policies unless restricted by conditions.

### `NotAction` vs `NotPrincipal` — dangerous combinations

```json
// DANGEROUS: Deny everything EXCEPT these actions — locks out non-MFA users from everything else
{
  "Effect": "Deny",
  "NotAction": ["iam:EnableMFADevice", "sts:GetSessionToken"],
  "Resource": "*",
  "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
}

// VERY DANGEROUS: Allow everyone EXCEPT this principal
// If used with Effect: Deny — it denies everyone ELSE
{
  "Effect": "Deny",
  "NotPrincipal": {"AWS": "arn:aws:iam::ACCOUNT:user/admin"},
  "Action": "s3:*",
  "Resource": "*"
}
```

`NotPrincipal` with `Effect: Deny` is almost never what you want — it denies all other principals.

### Resource-based policy + no identity-based policy = still works (same account)

For same-account principals, a resource-based policy alone can grant access without an identity-based policy. Cross-account requires both.

---

## IAM Policy Conditions Reference

```json
{
  "Condition": {
    // IP restriction
    "IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]},
    "NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},

    // MFA
    "Bool": {"aws:MultiFactorAuthPresent": "true"},
    "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"},
    "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"},

    // Time-based
    "DateGreaterThan": {"aws:CurrentTime": "2025-01-01T00:00:00Z"},
    "DateLessThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"},

    // Region
    "StringEquals": {"aws:RequestedRegion": "eu-west-1"},
    "StringNotEquals": {"aws:RequestedRegion": ["ap-southeast-1", "us-east-1"]},

    // VPC endpoint
    "StringEquals": {"aws:SourceVpce": "vpce-xxxxxxxxxxxxxxxxx"},
    "StringEquals": {"aws:SourceVpc": "vpc-xxxxxxxxxxxxxxxxx"},

    // SSL / TLS
    "Bool": {"aws:SecureTransport": "true"},

    // Tags (ABAC)
    "StringEquals": {
      "aws:RequestTag/Environment": "production",
      "aws:ResourceTag/Owner": "${aws:username}"
    }
  }
}
```

---

## ABAC (Attribute-Based Access Control)

ABAC uses tags to control access dynamically — scales better than RBAC for large organizations.

```json
{
  "Sid": "AccessByOwnerTag",
  "Effect": "Allow",
  "Action": [
    "ec2:StartInstances",
    "ec2:StopInstances"
  ],
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/Owner": "${aws:username}"
    }
  }
}
```

This lets each user start/stop only instances tagged with their username — no per-user policies needed.

---

## Certification Tips

- **Exam scenario**: "Least privilege for a Lambda that reads from S3 and writes to DynamoDB" → Create role with specific `s3:GetObject` on specific bucket ARN + `dynamodb:PutItem` on specific table ARN
- **Exam scenario**: "Users must use MFA before assuming admin role" → Trust policy with `aws:MultiFactorAuthPresent: true` condition
- **Exam scenario**: "Prevent all accounts in org from disabling GuardDuty" → SCP with `Deny` on `guardduty:DeleteDetector`
- **Exam scenario**: "Cross-account role — which policy controls who can assume?" → Trust policy (on the role in the target account)
- **Exam gotcha**: SCPs do not apply to the management/master account in AWS Organizations

---

## References

- [IAM User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/)
- [Policy Evaluation Logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [STS API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html)
- [IAM Policy Simulator](https://policysim.aws.amazon.com/)
