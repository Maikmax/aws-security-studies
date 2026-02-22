# AWS Security Hub — Setup, Findings, and Standards

> Marcus Paula | IT Engineer — TikTok EMEA  
> Covers: setup, standards (CIS, FSBP, PCI DSS), findings management, automation

---

## What Security Hub Does

Security Hub aggregates findings from:
- GuardDuty
- Inspector
- Macie
- IAM Access Analyzer
- Firewall Manager
- Detective
- Partner integrations (Crowdstrike, Splunk, etc.)
- AWS Config rules (compliance standards)

It normalizes findings into the AWS Security Finding Format (ASFF) and provides a unified dashboard.

---

## Setup

```bash
# Enable Security Hub
aws securityhub enable-security-hub \
  --enable-default-standards \
  --control-finding-generator SECURITY_CONTROL

# Enable additional standards
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"},
    {"StandardsArn": "arn:aws:securityhub:eu-west-1::standards/cis-aws-foundations-benchmark/v/1.4.0"},
    {"StandardsArn": "arn:aws:securityhub:eu-west-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
    {"StandardsArn": "arn:aws:securityhub:eu-west-1::standards/pci-dss/v/3.2.1"}
  ]'

# Check enabled standards
aws securityhub get-enabled-standards \
  --query 'StandardsSubscriptions[].{Standard:StandardsArn,Status:StandardsStatus}' \
  --output table
```

---

## Standards Overview

### 1. CIS AWS Foundations Benchmark

| Version | Coverage | Recommended For |
|---------|----------|----------------|
| v1.2 | 43 controls | Legacy, widely supported |
| v1.4 | 58 controls | Current standard |
| v2.0 | 63 controls | Latest, most comprehensive |

```bash
# Check CIS compliance score
aws securityhub describe-standards \
  --query 'Standards[?contains(StandardsArn, `cis`)].{Name:Name,ARN:StandardsArn}' \
  --output table

# Get CIS control status
aws securityhub describe-standards-controls \
  --standards-subscription-arn "arn:aws:securityhub:eu-west-1:ACCOUNT:subscription/cis-aws-foundations-benchmark/v/1.4.0" \
  --query 'Controls[?ControlStatus==`FAILED`].{ID:ControlId,Title:Title,Severity:SeverityRating}' \
  --output table
```

### 2. AWS Foundational Security Best Practices (FSBP)

275+ controls covering AWS services. More granular than CIS, service-specific.

```bash
# Failed FSBP controls
aws securityhub describe-standards-controls \
  --standards-subscription-arn "arn:aws:securityhub:eu-west-1:ACCOUNT:subscription/aws-foundational-security-best-practices/v/1.0.0" \
  --query 'Controls[?ControlStatus==`FAILED` && SeverityRating==`CRITICAL`].{ID:ControlId,Title:Title}' \
  --output table
```

### 3. PCI DSS v3.2.1

For environments handling cardholder data.

| PCI Requirement | Security Hub Control Category |
|----------------|-------------------------------|
| Req 1 | Network access controls (VPC, SG) |
| Req 2 | No default credentials | 
| Req 3 | Data at rest encryption |
| Req 4 | Data in transit encryption |
| Req 7 | Least privilege (IAM) |
| Req 8 | MFA, password policy |
| Req 10 | CloudTrail, logging |
| Req 11 | Inspector, GuardDuty |

---

## Findings Management

### Query findings by severity

```bash
# All CRITICAL active findings
aws securityhub get-findings \
  --filters '{
    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
  }' \
  --query 'Findings[].{Title:Title,Service:ProductName,Resource:Resources[0].Id,Updated:UpdatedAt}' \
  --output table | head -50
```

### Query by specific service

```bash
# GuardDuty findings only
aws securityhub get-findings \
  --filters '{
    "ProductName": [{"Value": "GuardDuty", "Comparison": "EQUALS"}],
    "SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --query 'Findings[].{Title:Title,Resource:Resources[0].Id,Time:UpdatedAt}' \
  --output table

# IAM Access Analyzer findings
aws securityhub get-findings \
  --filters '{
    "ProductName": [{"Value": "IAM Access Analyzer", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --query 'Findings[].{Title:Title,Resource:Resources[0].Id}' \
  --output table
```

### Suppress a finding (mark as not applicable)

```bash
aws securityhub batch-update-findings \
  --finding-identifiers '[{"Id": "FINDING_ID", "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"}]' \
  --workflow '{"Status": "SUPPRESSED"}' \
  --note '{"Text": "Exception: compensating control in place — VPN restricts access", "UpdatedBy": "marcus.paula"}'
```

---

## Security Score Tracking

```bash
# Get overall compliance score per standard
aws securityhub get-compliance-summary \
  --query 'ComplianceStatusCounts' \
  --output json

# Count passed vs failed controls per standard
aws securityhub describe-standards-controls \
  --standards-subscription-arn "arn:aws:securityhub:eu-west-1:ACCOUNT:subscription/cis-aws-foundations-benchmark/v/1.4.0" \
  --query 'Controls[].ControlStatus' \
  --output text | tr '\t' '\n' | sort | uniq -c
```

---

## Automated Remediation with EventBridge

Route Security Hub findings to Lambda for auto-remediation.

```json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "Severity": {
        "Label": ["CRITICAL"]
      },
      "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"],
      "RecordState": ["ACTIVE"],
      "Workflow": {
        "Status": ["NEW"]
      }
    }
  }
}
```

```python
# Lambda handler: auto-suppress false positives or trigger remediation
import boto3, json

securityhub = boto3.client('securityhub')

def handler(event, context):
    for finding in event['detail']['findings']:
        finding_id = finding['Id']
        product_arn = finding['ProductArn']
        title = finding['Title']
        severity = finding['Severity']['Label']
        resource = finding['Resources'][0]['Id'] if finding.get('Resources') else 'unknown'

        print(f"[{severity}] {title} — {resource}")

        # Example: notify and auto-acknowledge known false positive
        if 'S3.5' in title and 'logging-bucket' in resource:
            securityhub.batch_update_findings(
                FindingIdentifiers=[{'Id': finding_id, 'ProductArn': product_arn}],
                Workflow={'Status': 'SUPPRESSED'},
                Note={'Text': 'Logging bucket — SSL enforcement exception', 'UpdatedBy': 'auto-remediation'}
            )
```

---

## Multi-Account Setup (AWS Organizations)

```bash
# Designate a Security Hub administrator account
aws securityhub enable-organization-admin-account \
  --admin-account-id SECURITY_ACCOUNT_ID

# In the admin account: auto-enable for new org members
aws securityhub update-organization-configuration \
  --auto-enable \
  --auto-enable-standards SECURITY_CONTROL

# List member accounts
aws securityhub list-members \
  --query 'Members[].{Account:AccountId,Status:MemberStatus,Email:Email}' \
  --output table
```

---

## Key Metrics to Track

| Metric | Target | Frequency |
|--------|--------|-----------|
| CRITICAL findings (new) | 0 unresolved > 24h | Daily |
| HIGH findings (new) | 0 unresolved > 7 days | Weekly |
| CIS compliance score | > 90% | Weekly |
| FSBP compliance score | > 85% | Monthly |
| Mean time to remediate CRITICAL | < 4 hours | Monthly |
| Suppressed findings ratio | < 5% | Monthly |

---

## References

- [Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [ASFF (Finding Format)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
- [Security Hub Automated Response](https://aws.amazon.com/solutions/implementations/aws-security-hub-automated-response-and-remediation/)
- [CIS Benchmark in Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
