# AWS Security Studies

> **Marcus Paula** | IT Engineer — TikTok EMEA | Dublin, Ireland
> 14x AWS Certifications | Cloud Security | IAM | Compliance

Hands-on AWS security practice: IAM auditing, cloud compliance automation
and security posture assessment aligned with CIS AWS Foundations Benchmark.

---

## Operational Context

Cloud security skills applied in enterprise environments managing hybrid
infrastructure across EMEA. Scripts and notes reflect real-world scenarios
including IAM lifecycle management, asset visibility and compliance reporting.

| KPI | Context |
|-----|---------|
| **Security Incident Rate** | Zero IAM-related incidents during EMEA expansion (Madrid · Milan) |
| **Automation Rate** | IAM audit previously manual → scripted, reducing review cycle by ~60% |
| **Change Success Rate** | 100% on IAM policy changes across 3 EMEA sites with zero rollbacks |
| **Risk Exposure Index** | Eliminated standing root access keys and enforced MFA across accounts |
| **IT Budget as % of Revenue** | Automated compliance checks removed need for third-party audit tooling |
| **Audit Readiness** | CIS Benchmark checks automated — audit evidence generated on demand |

---

## Contents

```
iam/
  aws-iam-audit.py      # CIS AWS Foundations Benchmark v1.4 — automated checks
```

### aws-iam-audit.py

Evaluates AWS account security posture against CIS Benchmark.

**Checks covered:**

| CIS Control | Check |
|-------------|-------|
| 1.1 | Root account MFA enabled |
| 1.4 | No active root access keys |
| 1.5–1.11 | Password policy (length, complexity, rotation, reuse) |
| 1.2 | MFA on all console users |
| 1.13 | Access keys rotated within 90 days |
| 1.16 | No AdministratorAccess policy attached directly to users |
| S3 | Public access block enabled on all buckets |

```bash
# Default region: eu-west-1
python3 iam/aws-iam-audit.py

# Named profile, different region
python3 iam/aws-iam-audit.py --profile prod --region eu-central-1
```

Output: console summary + timestamped JSON report in `audit-reports/`.

---

## AWS Certifications (14)

| Certificate | Year |
|------------|------|
| AWS Foundations: Securing Your AWS Cloud | 2020 |
| Authentication and Authorization with AWS IAM | 2020 |
| Introduction to AWS Identity and Access Management | 2020 |
| Introduction to AWS Security Token Services (STS) | 2020 |
| Introduction to Amazon Inspector | 2020 |
| Introduction to Amazon Macie | 2020 |
| Introduction to Data Encryption | 2020 |
| Understanding Amazon EBS Volume Encryption | 2020 |
| Protect Your Web-facing Workloads with AWS Security Services | 2020 |
| AWS Certificate Manager — Private Certificate Authority | 2020 |
| Differences Between Security Groups and NACLs | 2020 |
| Introduction to AWS Artifact | 2020 |
| AWS Foundations: Machine Learning Basics | 2020 |
| Database, Analytics & Management | 2019 |

---

## Topics Covered

```
IAM        — Identity and access management, roles, policies, STS
Inspector  — Vulnerability assessment and findings
Macie      — Data classification and sensitive data detection
KMS        — Key management and encryption at rest
VPC        — Security groups, NACLs, flow logs
WAF/Shield — Web application and DDoS protection
Artifact   — Compliance reports and agreements
```

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Marcus_Paula-0077B5?style=flat-square&logo=linkedin)](https://linkedin.com/in/marcuspaula)
[![GitHub](https://img.shields.io/badge/GitHub-Maikmax-181717?style=flat-square&logo=github)](https://github.com/Maikmax)
