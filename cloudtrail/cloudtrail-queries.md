# CloudTrail Ready-to-Use Queries

> Marcus Paula | IT Engineer — TikTok EMEA  
> Reference collection: IR, privilege escalation, compliance, anomaly detection

All queries use `aws cloudtrail lookup-events` (90-day lookback) or CloudWatch Logs Insights.

---

## Authentication & Identity

### Root account usage (any action)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time $(date -d '30 days ago' --iso-8601=seconds) \
  --query 'Events[].{Time:EventTime,Event:EventName}' \
  --output table
```

### Console logins without MFA

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time $(date -d '7 days ago' --iso-8601=seconds) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        extra = e.get('additionalEventData', {})
        if extra.get('MFAUsed') != 'Yes':
            ident = e.get('userIdentity', {})
            print(e['eventTime'], ident.get('userName', ident.get('arn')), e.get('sourceIPAddress'), '— NO MFA')
    except:
        pass
"
```

### Failed logins (brute force detection)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import json, sys, collections
failures = collections.defaultdict(list)
for line in sys.stdin:
    try:
        e = json.loads(line)
        resp = e.get('responseElements', {})
        if resp and 'ConsoleLogin' in str(resp):
            if 'Failure' in str(resp):
                ip = e.get('sourceIPAddress', 'unknown')
                user = e.get('userIdentity', {}).get('userName', 'unknown')
                failures[ip].append(user)
    except:
        pass
for ip, users in sorted(failures.items(), key=lambda x: -len(x[1])):
    print(f'{len(users)} failures from {ip}: {set(users)}')
"
```

---

## Privilege Escalation

### Any admin policy attached (users or roles)

```bash
for event in AttachUserPolicy AttachRolePolicy; do
  echo "=== $event ===" 
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '30 days ago' --iso-8601=seconds) \
    --query 'Events[].CloudTrailEvent' \
    --output text | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        req = e.get('requestParameters', {})
        policy = req.get('policyArn', '')
        if 'Administrator' in policy or 'PowerUser' in policy or 'FullAccess' in policy:
            ident = e.get('userIdentity', {})
            target = req.get('userName', req.get('roleName', '?'))
            print(e['eventTime'], 'BY:', ident.get('arn','?'), 'TO:', target, 'POLICY:', policy)
    except:
        pass
"
done
```

### Inline policy creation (often used to bypass SCPs)

```bash
for event in PutUserPolicy PutRolePolicy PutGroupPolicy; do
  echo "=== $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '30 days ago' --iso-8601=seconds) \
    --query 'Events[].{Time:EventTime,User:Username,Event:CloudTrailEvent}' \
    --output table
done
```

### CreatePolicyVersion (replacing managed policy — common escalation path)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreatePolicyVersion \
  --start-time $(date -d '30 days ago' --iso-8601=seconds) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        req = e.get('requestParameters', {})
        ident = e.get('userIdentity', {})
        print(e['eventTime'], ident.get('arn','?'), req.get('policyArn','?'), 'SetDefault:', req.get('setAsDefault','?'))
    except:
        pass
"
```

### AssumeRole chaining (lateral movement / cross-account)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -d '7 days ago' --iso-8601=seconds) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        req = e.get('requestParameters', {})
        ident = e.get('userIdentity', {})
        src = ident.get('arn', ident.get('principalId', '?'))
        dst = req.get('roleArn', '?')
        # Highlight cross-account assumptions
        src_account = src.split(':')[4] if ':' in src else '?'
        dst_account = dst.split(':')[4] if ':' in dst else '?'
        flag = ' *** CROSS-ACCOUNT ***' if src_account != dst_account and src_account != '?' else ''
        print(e['eventTime'], src, '->', dst, flag)
    except:
        pass
"
```

---

## IAM Changes

### New users or access keys created

```bash
for event in CreateUser CreateAccessKey CreateLoginProfile; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '30 days ago' --iso-8601=seconds) \
    --query 'Events[].{Time:EventTime,By:Username,Event:EventName}' \
    --output table
done
```

### Users deleted (potential cover-up)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUser \
  --start-time $(date -d '90 days ago' --iso-8601=seconds) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        req = e.get('requestParameters', {})
        ident = e.get('userIdentity', {})
        print(e['eventTime'], 'BY:', ident.get('arn','?'), 'DELETED:', req.get('userName','?'))
    except:
        pass
"
```

### Password policy changes

```bash
for event in UpdateAccountPasswordPolicy DeleteAccountPasswordPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '90 days ago' --iso-8601=seconds) \
    --query 'Events[].{Time:EventTime,By:Username,Event:EventName}' \
    --output table
done
```

---

## Audit Evasion Detection

### CloudTrail disabled, deleted, or modified

```bash
for event in DeleteTrail StopLogging UpdateTrail; do
  echo "=== ALERT: $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '90 days ago' --iso-8601=seconds) \
    --query 'Events[].{Time:EventTime,By:Username}' \
    --output table
done
```

### GuardDuty disabled

```bash
for event in DeleteDetector DisassociateFromMasterAccount; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '90 days ago' --iso-8601=seconds) \
    --query 'Events[].{Time:EventTime,By:Username}' \
    --output table
done
```

### Config recorder stopped

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopConfigurationRecorder \
  --start-time $(date -d '90 days ago' --iso-8601=seconds) \
  --query 'Events[].{Time:EventTime,By:Username}' \
  --output table
```

---

## S3 Data Access

### List all buckets accessed (by whom)

```bash
for event in ListBuckets GetObject PutObject DeleteObject; do
  echo "=== $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
    --query 'Events[].{Time:EventTime,User:Username,Resource:Resources}' \
    --output table | head -30
done
```

### GetObject calls from unexpected IPs

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import json, sys, ipaddress
INTERNAL_RANGES = [ipaddress.ip_network(r) for r in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']]

def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in r for r in INTERNAL_RANGES)
    except:
        return True

for line in sys.stdin:
    try:
        e = json.loads(line)
        ip = e.get('sourceIPAddress', '')
        if not is_internal(ip) and not 'amazonaws.com' in ip:
            ident = e.get('userIdentity', {})
            req = e.get('requestParameters', {})
            print(e['eventTime'], ip, ident.get('arn','?'), req.get('bucketName','?'), req.get('key','?'))
    except:
        pass
"
```

---

## CloudWatch Logs Insights Queries (copy-paste ready)

### All events by a specific principal

```
fields eventTime, eventSource, eventName, sourceIPAddress, errorCode
| filter userIdentity.arn like /arn:aws:iam::ACCOUNT:user\/USERNAME/
| sort eventTime desc
| limit 200
```

### Top 20 API callers by volume

```
fields eventTime, eventName, userIdentity.arn
| stats count(*) as calls by userIdentity.arn
| sort calls desc
| limit 20
```

### Access Denied errors (potential recon or misconfiguration)

```
fields eventTime, eventName, userIdentity.arn, sourceIPAddress, errorMessage
| filter errorCode = "AccessDenied"
| stats count(*) as denied by userIdentity.arn, eventName
| sort denied desc
| limit 50
```

### Unusual API calls (not read-only, not from known CIDR)

```
fields eventTime, eventName, userIdentity.arn, sourceIPAddress
| filter not (eventName like /^Get/ or eventName like /^List/ or eventName like /^Describe/)
| filter sourceIPAddress not like /^10\./ and sourceIPAddress not like /^172\.1[6-9]\./ and sourceIPAddress not like /^172\.2/ and sourceIPAddress not like /^172\.3[01]\./ and sourceIPAddress not like /^192\.168\./
| sort eventTime desc
| limit 100
```

### Security group changes (network exposure)

```
fields eventTime, eventName, userIdentity.arn, requestParameters.groupId
| filter eventName in ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
                        "RevokeSecurityGroupIngress", "CreateSecurityGroup", "DeleteSecurityGroup"]
| sort eventTime desc
| limit 50
```

---

## References

- [CloudTrail Event Names](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html)
- [Detecting Privilege Escalation in AWS](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [CloudWatch Logs Insights Syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)
