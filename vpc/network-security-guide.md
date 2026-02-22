# AWS Network Security — Defense in Depth

> Marcus Paula | IT Engineer — TikTok EMEA  
> Covers: WAF, Shield, GuardDuty, Inspector, layered network controls

---

## Defense in Depth Model

```
Internet
    │
    ▼
[AWS Shield Advanced]  ← DDoS protection (L3/L4/L7)
    │
    ▼
[AWS WAF]             ← Web Application Firewall (L7: SQL injection, XSS, rate limiting)
    │
    ▼
[CloudFront / ALB]    ← Load balancer / CDN
    │
    ▼
[Security Group]      ← Stateful instance-level firewall
    │
    ▼
[NACL]                ← Stateless subnet-level filter
    │
    ▼
[VPC]                 ← Network isolation boundary
    │
    ▼
[EC2 / ECS / Lambda]  ← Workload
    │
    ▼
[Inspector]           ← Host-based vulnerability assessment
```

---

## 1. AWS WAF

### Recommended rule groups (managed rules)

```bash
# Create WebACL with AWS managed rule groups
aws wafv2 create-web-acl \
  --name "production-waf" \
  --scope REGIONAL \
  --region eu-west-1 \
  --default-action '{"Allow": {}}' \
  --visibility-config '{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"production-waf"}' \
  --rules '[
    {
      "Name": "AWSManagedRulesCommonRuleSet",
      "Priority": 1,
      "OverrideAction": {"None": {}},
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet"
        }
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "CommonRules"
      }
    },
    {
      "Name": "AWSManagedRulesKnownBadInputsRuleSet",
      "Priority": 2,
      "OverrideAction": {"None": {}},
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesKnownBadInputsRuleSet"
        }
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "KnownBadInputs"
      }
    }
  ]'
```

### Rate limiting rule (DDoS + brute force)

```bash
# Add rate-based rule: max 500 requests per 5 minutes per IP
aws wafv2 create-rule-group \
  --name "rate-limiting" \
  --scope REGIONAL \
  --capacity 10 \
  --rules '[{
    "Name": "RateLimitPerIP",
    "Priority": 1,
    "Action": {"Block": {}},
    "Statement": {
      "RateBasedStatement": {
        "Limit": 500,
        "AggregateKeyType": "IP"
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitPerIP"
    }
  }]' \
  --visibility-config '{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"rate-limiting"}'
```

### WAF managed rule groups reference

| Rule Group | Blocks | Priority |
|------------|--------|----------|
| AWSManagedRulesCommonRuleSet | OWASP Top 10, common web exploits | Always use |
| AWSManagedRulesKnownBadInputsRuleSet | Log4j, Spring4Shell, SSRF | Always use |
| AWSManagedRulesSQLiRuleSet | SQL injection attacks | Use if DB-backed |
| AWSManagedRulesLinuxRuleSet | Linux-specific exploits | Use if Linux workloads |
| AWSManagedRulesWordPressRuleSet | WordPress exploits | Use if WordPress |
| AWSManagedRulesAmazonIpReputationList | Known malicious IPs | Recommended |
| AWSManagedRulesAnonymousIpList | Tor, VPN exit nodes | Use if needed |

---

## 2. AWS Shield

| Tier | Protection | Cost | Recommended For |
|------|------------|------|----------------|
| Shield Standard | L3/L4 DDoS, always on | Free | All AWS accounts |
| Shield Advanced | L7 DDoS, DRT access, cost protection | ~$3,000/month | Production web apps |

```bash
# Subscribe to Shield Advanced
aws shield create-subscription

# Add a resource to Shield Advanced protection
aws shield create-protection \
  --name "production-alb" \
  --resource-arn arn:aws:elasticloadbalancing:eu-west-1:ACCOUNT:loadbalancer/app/prod-alb/xxxxx

# List active protections
aws shield list-protections \
  --query 'Protections[].{Name:Name,Resource:ResourceArn}' \
  --output table

# Check for active DDoS attacks
aws shield describe-attacks \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --end-time $(date --iso-8601=seconds) \
  --query 'Attacks[].{ID:AttackId,Resource:ResourceArn,Start:StartTime,End:EndTime}' \
  --output table
```

---

## 3. Amazon GuardDuty

GuardDuty is a threat detection service that continuously monitors CloudTrail, VPC Flow Logs, DNS logs, and S3 data events.

### Setup and verification

```bash
# Check if GuardDuty is enabled
aws guardduty list-detectors

# Enable GuardDuty (if not enabled)
DETECTOR_ID=$(aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --query 'DetectorId' --output text)

# Enable S3 protection (detects malicious S3 API activity)
aws guardduty update-detector \
  --detector-id "$DETECTOR_ID" \
  --data-sources '{"S3Logs":{"Enable":true}}'

# Enable EKS protection
aws guardduty update-detector \
  --detector-id "$DETECTOR_ID" \
  --features '[{"Name":"EKS_AUDIT_LOGS","Status":"ENABLED"}]'

# Enable Malware Protection for EC2
aws guardduty update-detector \
  --detector-id "$DETECTOR_ID" \
  --features '[{"Name":"EBS_MALWARE_PROTECTION","Status":"ENABLED"}]'
```

### Key GuardDuty finding types

| Category | Finding | Severity |
|----------|---------|----------|
| IAM | UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B | HIGH |
| IAM | PrivilegeEscalation:IAMUser/AdministrativePermissions | HIGH |
| IAM | PersistenceUsage:IAMUser/NetworkPermissions | MEDIUM |
| Cryptocurrency | CryptoCurrency:EC2/BitcoinTool.B | HIGH |
| Backdoor | Backdoor:EC2/C&CActivity.B | HIGH |
| Recon | Recon:IAMUser/MaliciousIPCaller | MEDIUM |
| S3 | Discovery:S3/MaliciousIPCaller | HIGH |
| S3 | Exfiltration:S3/MaliciousIPCaller | HIGH |
| DNS | Trojan:EC2/DNSDataExfiltration | HIGH |
| Network | Trojan:EC2/PortProbeUnprotectedPort | LOW |

```bash
# List HIGH and CRITICAL findings
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
  --query 'FindingIds' --output text | tr '\t' '\n' | while read id; do
    aws guardduty get-findings \
      --detector-id "$DETECTOR_ID" \
      --finding-ids "$id" \
      --query 'Findings[].{Time:UpdatedAt,Type:Type,Severity:Severity,Resource:Resource.ResourceType}' \
      --output table
done
```

---

## 4. Amazon Inspector

Inspector performs automated vulnerability assessments on EC2 instances and container images.

```bash
# Enable Inspector v2 for the account
aws inspector2 enable \
  --resource-types EC2 ECR LAMBDA LAMBDA_CODE

# Check Inspector findings summary
aws inspector2 list-findings \
  --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
  --query 'findings[].{Title:title,Severity:severity,Resource:resources[0].id,Score:inspectorScore}' \
  --output table | head -30

# Critical vulnerabilities on EC2
aws inspector2 list-findings \
  --filter-criteria '{
    "findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}],
    "severity":[{"comparison":"EQUALS","value":"CRITICAL"}],
    "resourceType":[{"comparison":"EQUALS","value":"AWS_EC2_INSTANCE"}]
  }' \
  --query 'findings[].{CVE:packageVulnerabilityDetails.vulnerabilityId,Instance:resources[0].id,Score:inspectorScore}' \
  --output table
```

### Inspector coverage check

```bash
# Check which instances are covered
aws inspector2 list-coverage \
  --query 'coveredResources[].{Resource:resourceId,Type:resourceType,ScanType:scanType,Status:scanStatus.statusCode}' \
  --output table
```

---

## 5. Amazon Macie

Macie discovers and classifies sensitive data in S3 (PII, credentials, financial data).

```bash
# Enable Macie
aws macie2 enable-macie

# Create a classification job for all S3 buckets
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "full-s3-classification-$(date +%Y%m%d)" \
  --s3-job-definition '{
    "bucketDefinitions": [],
    "scoping": {
      "includes": {
        "and": []
      }
    }
  }' \
  --sampling-percentage 100

# Check findings (sensitive data discovered)
aws macie2 list-findings \
  --query 'findingIds' --output text | tr '\t' '\n' | head -10 | while read id; do
    aws macie2 get-findings \
      --finding-ids "$id" \
      --query 'findings[].{Type:type,Bucket:resourcesAffected.s3Bucket.name,Count:count}' \
      --output table
done
```

---

## 6. Network Monitoring Strategy

### What to alert on

| Event | Detection Source | Action |
|-------|-----------------|--------|
| SSH from 0.0.0.0/0 | Security Hub / Config | Immediate remediation |
| VPC Flow Log REJECT spike | CloudWatch Alarm | Investigate source |
| GuardDuty HIGH/CRITICAL | EventBridge → SNS | Page on-call |
| WAF block rate spike | CloudWatch Alarm | Review WAF rules |
| New IGW attached to VPC | CloudTrail / Config | Review immediately |
| Security group rule change | CloudTrail / Config | Review if to 0.0.0.0/0 |
| Unusual DNS queries | GuardDuty | DNS data exfil check |

### CloudWatch alarm for Security Group changes

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "SecurityGroupChanges" \
  --metric-name "SecurityGroupEventCount" \
  --namespace "CloudTrailMetrics" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:eu-west-1:ACCOUNT:security-alerts \
  --alarm-description "Alert on any Security Group modification"
```

---

## References

- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
- [AWS Shield Advanced](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Amazon Inspector](https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html)
- [Amazon Macie](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
