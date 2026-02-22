# AWS Security Studies

> **Marcus Paula** | IT Engineer — TikTok EMEA | Dublin, Ireland  
> 14x AWS Certifications | Cloud Security | IAM | Zero Trust | CIS Benchmark | DFIR

[![CIS Benchmark](https://img.shields.io/badge/CIS_AWS-Benchmark_v1.4%2Fv2.0-blue?style=flat-square)](https://www.cisecurity.org/benchmark/amazon_web_services)
[![AWS Certified](https://img.shields.io/badge/AWS-14x_Certified-FF9900?style=flat-square&logo=amazon-aws)](https://github.com/Maikmax/certifications)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Marcus_Paula-0077B5?style=flat-square&logo=linkedin)](https://linkedin.com/in/marcuspaula)
[![GitHub](https://img.shields.io/badge/GitHub-Maikmax-181717?style=flat-square&logo=github)](https://github.com/Maikmax)

---

## About

Hands-on AWS security practice: IAM auditing, S3 hardening, network defense, CloudTrail analysis,
and compliance automation aligned with the CIS AWS Foundations Benchmark.

Content reflects real-world patterns applied in enterprise environments managing hybrid infrastructure
across EMEA — including IAM lifecycle management, asset visibility, compliance reporting, and incident response.

---

## Operational Context

| Metric | Context |
|--------|---------|
| **Security Incidents** | Zero IAM-related incidents during EMEA expansion (Dublin · Madrid · Milan) |
| **IAM Automation** | Audit cycle reduced ~60% through scripted CIS checks |
| **Change Success Rate** | 100% on IAM policy changes across 3 EMEA sites, zero rollbacks |
| **Root Access** | Eliminated standing root access keys, enforced MFA across all accounts |
| **Audit Readiness** | CIS Benchmark checks automated — compliance evidence generated on demand |
| **Standards Covered** | CIS AWS Foundations Benchmark v1.4/v2.0 · AWS FSBP · ISO 27001 alignment |

---

## Repository Structure

```
aws-security-studies/
├── iam/
│   ├── aws-iam-audit.py              # CIS IAM checks — automated auditor script
│   ├── iam-best-practices.md         # CIS + Well-Architected IAM controls
│   └── least-privilege-guide.md      # Practical least privilege implementation
│
├── s3/
│   ├── s3-security-audit.py          # S3 audit: public access, ACLs, encryption, logging
│   └── s3-security-checklist.md      # Hardening checklist: encryption, versioning, MFA Delete
│
├── cloudtrail/
│   ├── cloudtrail-analysis.md        # CloudTrail for IR and compliance evidence
│   └── cloudtrail-queries.md         # Ready-to-use queries: root usage, escalation, evasion
│
├── vpc/
│   ├── vpc-security-checklist.md     # SGs, NACLs, Flow Logs, VPC Endpoints
│   └── network-security-guide.md     # Defense in depth: WAF, Shield, GuardDuty, Inspector
│
├── compliance/
│   ├── cis-aws-benchmark.md          # CIS AWS Foundations Benchmark — all controls mapped
│   └── aws-security-hub-guide.md     # Security Hub setup, standards, findings management
│
└── study-notes/
    ├── aws-iam-cert-notes.md         # IAM study notes from 14 AWS certifications
    └── aws-security-services.md      # Service reference: Inspector, Macie, GuardDuty, KMS, etc.
```

---

## IAM

### `iam/aws-iam-audit.py`

Automated security posture check against CIS AWS Foundations Benchmark v1.4.

```bash
# Default region: eu-west-1
python3 iam/aws-iam-audit.py

# Named profile, specific region
python3 iam/aws-iam-audit.py --profile prod --region eu-central-1
```

| CIS Control | Check |
|-------------|-------|
| 1.1 | Root account MFA enabled |
| 1.4 | No active root access keys |
| 1.5–1.11 | Password policy (length, complexity, rotation, reuse) |
| 1.2 | MFA enabled on all console users |
| 1.13 | Access keys rotated within 90 days |
| 1.16 | No AdministratorAccess directly attached to users |
| S3 | Public access block enabled on all buckets |

Output: console summary + timestamped JSON report in `audit-reports/`.

### `iam/iam-best-practices.md`

Root hardening, password policy, MFA enforcement, access key rotation, permission boundaries, and IAM Access Analyzer setup. Includes ready-to-run CLI commands and IAM policy examples.

### `iam/least-privilege-guide.md`

Phase-by-phase guide: discovery (Access Advisor, CloudTrail, Access Analyzer), policy construction templates, permission boundaries, privilege escalation prevention, and quarterly review cadence.

---

## S3

### `s3/s3-security-audit.py`

Audits every S3 bucket for:

```bash
python3 s3/s3-security-audit.py

# Single bucket
python3 s3/s3-security-audit.py --bucket my-bucket-name

# Named profile
python3 s3/s3-security-audit.py --profile prod --region eu-west-1
```

| Check | CIS Ref |
|-------|---------|
| Block Public Access (all 4 settings) | CIS 2.1.5 |
| Public ACL grants | CIS 2.1.2 |
| Bucket policy public principal | — |
| Default encryption (SSE-S3 / SSE-KMS) | CIS 2.1.1 |
| Versioning enabled | CIS 2.1.3 |
| MFA Delete | CIS 2.1.3 |
| Server access logging | CIS 2.1.4 |
| SSL-only access (deny HTTP) | AWS Sec |

### `s3/s3-security-checklist.md`

Covers: Block Public Access, encryption decision matrix, versioning + MFA Delete, access logging, SSL enforcement policy, lifecycle rules, Security Hub S3 controls coverage, and a full bucket hardening script.

---

## CloudTrail

### `cloudtrail/cloudtrail-analysis.md`

- Verifying trail configuration (multi-region, log validation, CW Logs)
- IR timeline reconstruction (scope → compromised principal → lateral movement → exfiltration)
- Compliance evidence generation for auditors
- CloudWatch Logs Insights queries
- Athena table setup for querying logs at scale

### `cloudtrail/cloudtrail-queries.md`

Copy-paste ready queries covering:

| Category | Queries |
|----------|---------|
| Authentication | Root usage, MFA bypass, failed logins |
| Privilege Escalation | Admin policy attach, inline policies, CreatePolicyVersion, AssumeRole chains |
| IAM Changes | New users, access keys, deleted users, password policy changes |
| Audit Evasion | CloudTrail disable/delete, GuardDuty disable, Config stop |
| S3 Data Access | GetObject from unusual IPs, bulk access |
| CloudWatch Logs Insights | Top callers, AccessDenied, unusual write operations, SG changes |

---

## VPC

### `vpc/vpc-security-checklist.md`

Security Groups vs NACLs reference, unrestricted inbound rule detection, VPC Flow Log setup and analysis, NACL structure for 3-tier VPC, VPC Endpoints (S3, DynamoDB, SSM, ECR), default VPC handling.

### `vpc/network-security-guide.md`

Defense-in-depth architecture covering WAF (managed rules, rate limiting), Shield Standard vs Advanced, GuardDuty (finding categories, all features), Inspector v2, and Macie. Includes alerting strategy and EventBridge integration patterns.

---

## Compliance

### `compliance/cis-aws-benchmark.md`

Full CIS AWS Foundations Benchmark v1.4/v2.0 control reference with verification commands for every control across IAM, S3, Logging, Monitoring (metric filters + alarm patterns), and Networking. Includes quick compliance score script.

### `compliance/aws-security-hub-guide.md`

Security Hub setup, standards (CIS, FSBP, PCI DSS), findings queries, suppression workflow, compliance score tracking, EventBridge auto-remediation pattern, and multi-account Organizations setup.

---

## Study Notes

### `study-notes/aws-iam-cert-notes.md`

IAM concepts from 14 AWS certifications: principal types, policy evaluation logic (including cross-account), STS and federation (SAML 2.0, OIDC), policy types comparison, managed vs inline policies, `iam:PassRole`, `NotAction`/`NotPrincipal` gotchas, condition keys reference, ABAC patterns.

### `study-notes/aws-security-services.md`

Quick reference for all AWS security services: GuardDuty (finding types, all features), Inspector v2 (classic vs v2), Macie (data identifiers), KMS (key types, envelope encryption), Secrets Manager (rotation, comparison vs SSM), Config (managed rules), and Artifact.

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

## CIS AWS Benchmark Coverage

| Section | Controls | Coverage |
|---------|---------|---------|
| 1 — IAM | 21 controls | `iam/aws-iam-audit.py` + `iam/iam-best-practices.md` |
| 2 — Storage (S3, EBS, RDS) | 7 controls | `s3/s3-security-audit.py` + `s3/s3-security-checklist.md` |
| 3 — Logging | 11 controls | `cloudtrail/cloudtrail-analysis.md` |
| 4 — Monitoring | 14 controls | `compliance/cis-aws-benchmark.md` (metric filter patterns) |
| 5 — Networking | 6 controls | `vpc/vpc-security-checklist.md` |

---

## Requirements

```
Python 3.8+
boto3 (pip install boto3)    # for Pythonic AWS access
AWS CLI v2                   # for bash-based checks
IAM permissions: ReadOnlyAccess (minimum) + SecurityAudit
```

---

## Related Repositories

| Repository | Description |
|-----------|-------------|
| [zero-trust-iam](https://github.com/Maikmax/zero-trust-iam) | Zero Trust IAM architecture patterns |
| [dfir-investigations](https://github.com/Maikmax/dfir-investigations) | Digital forensics and incident response |
| [certifications](https://github.com/Maikmax/certifications) | 42+ certification portfolio |
| [cybersecurity-labs](https://github.com/Maikmax/cybersecurity-labs) | HackTheBox, TryHackMe, CTF writeups |
