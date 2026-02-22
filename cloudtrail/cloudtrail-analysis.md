# CloudTrail Log Analysis — IR and Compliance

> Marcus Paula | IT Engineer — TikTok EMEA  
> Used for incident response, compliance evidence, and anomaly detection

---

## What CloudTrail Captures

CloudTrail records API calls made to AWS services. Each event contains:

| Field | Description | Example |
|-------|-------------|---------|
| `eventTime` | UTC timestamp of the call | `2025-06-15T14:23:01Z` |
| `eventSource` | AWS service receiving the call | `iam.amazonaws.com` |
| `eventName` | API action called | `CreateUser` |
| `userIdentity` | Who made the call | IAM user, role, service |
| `sourceIPAddress` | IP of the caller | `203.0.113.10` |
| `requestParameters` | Input to the API | Username, bucket name |
| `responseElements` | Output from the API | Created resource ARN |
| `errorCode` | Error if request failed | `AccessDenied` |
| `errorMessage` | Human-readable error | Policy denial reason |

---

## Setup: Ensure CloudTrail Is Configured Correctly

```bash
# List all trails
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,Bucket:S3BucketName,Global:IncludeGlobalServiceEvents,MultiRegion:IsMultiRegionTrail}'

# Verify logging is active
aws cloudtrail get-trail-status \
  --name arn:aws:cloudtrail:eu-west-1:ACCOUNT:trail/TRAIL_NAME \
  --query '{Logging:IsLogging,LastDelivery:LatestDeliveryTime}'

# Check log file validation (detect tampering)
aws cloudtrail get-trail \
  --name TRAIL_NAME \
  --query 'Trail.LogFileValidationEnabled'
```

### Minimum recommended trail configuration

```bash
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name cloudtrail-logs-ACCOUNT \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation

# Enable CloudWatch Logs delivery
aws cloudtrail update-trail \
  --name organization-trail \
  --cloud-watch-logs-log-group-arn arn:aws:logs:eu-west-1:ACCOUNT:log-group:CloudTrail/DefaultLogGroup:* \
  --cloud-watch-logs-role-arn arn:aws:iam::ACCOUNT:role/CloudTrail_CloudWatchLogs_Role

aws cloudtrail start-logging --name organization-trail
```

---

## Log Storage and Retention

### S3 bucket structure

```
cloudtrail-logs-ACCOUNT/
  AWSLogs/
    ACCOUNT_ID/
      CloudTrail/
        REGION/
          YYYY/
            MM/
              DD/
                ACCOUNT_ID_CloudTrail_REGION_YYYYMMDDTHHMMSSZ_SUFFIX.json.gz
```

### Download and decompress logs

```bash
# List logs for today
aws s3 ls "s3://cloudtrail-logs-ACCOUNT/AWSLogs/ACCOUNT/CloudTrail/eu-west-1/$(date +%Y/%m/%d)/"

# Download and decompress a log file
aws s3 cp "s3://cloudtrail-logs-ACCOUNT/AWSLogs/ACCOUNT/CloudTrail/eu-west-1/2025/06/15/LOG_FILE.json.gz" .
gunzip LOG_FILE.json.gz

# Parse events — pretty print
cat LOG_FILE.json | python3 -m json.tool | less

# Extract specific fields
cat LOG_FILE.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for event in data.get('Records', []):
    print(event['eventTime'], event['eventName'], event.get('userIdentity', {}).get('arn', 'unknown'))
"
```

---

## Incident Response: Timeline Reconstruction

### Step 1 — Establish scope (which account, which timeframe)

```bash
# Who called what in the last 24 hours (using CloudTrail lookup — max 90 days lookback)
aws cloudtrail lookup-events \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --query 'Events[].{Time:EventTime,Event:EventName,User:Username,IP:CloudTrailEvent}' \
  --output table | head -100
```

### Step 2 — Identify the compromised principal

```bash
# All events from a specific IAM user (last 7 days)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=SUSPECT_USER \
  --start-time $(date -d '7 days ago' --iso-8601=seconds) \
  --query 'Events[].{Time:EventTime,Event:EventName,Source:CloudTrailEvent}' \
  --output json | python3 -c "
import json, sys
events = json.load(sys.stdin)
for e in events:
    raw = json.loads(e.get('Source', '{}'))
    print(e['Time'], e['Event'], raw.get('sourceIPAddress', ''))
" | sort
```

### Step 3 — Track lateral movement

```bash
# AssumeRole events (role chaining, cross-account moves)
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
        print(e['eventTime'], ident.get('arn','?'), '->', req.get('roleArn','?'))
    except:
        pass
"
```

### Step 4 — Check for data exfiltration indicators

```bash
# Large S3 GetObject or ListBucket activity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import json, sys, collections
calls = collections.Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        user = e.get('userIdentity', {}).get('arn', 'unknown')
        calls[user] += 1
    except:
        pass
for user, count in calls.most_common(20):
    print(f'{count:6d}  {user}')
"
```

---

## Compliance Evidence Generation

### Evidence for auditors: who had admin access?

```bash
# All AttachRolePolicy and AttachUserPolicy events
for event in AttachRolePolicy AttachUserPolicy PutRolePolicy PutUserPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event" \
    --start-time $(date -d '90 days ago' --iso-8601=seconds) \
    --query 'Events[].{Time:EventTime,Event:EventName,User:Username}' \
    --output table
done
```

### Evidence: no root usage in period

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time "$AUDIT_START" \
  --end-time "$AUDIT_END" \
  --query 'Events[].{Time:EventTime,Event:EventName,IP:CloudTrailEvent}' \
  --output table
```

---

## CloudWatch Logs Insights — Querying CloudTrail in CWL

After routing CloudTrail to CloudWatch Logs:

```
# All API calls by source IP (detect unusual origins)
fields eventTime, eventName, userIdentity.arn, sourceIPAddress
| filter sourceIPAddress not like /^10\./
  and sourceIPAddress not like /^172\.16\./
  and sourceIPAddress not like /^192\.168\./
| stats count(*) as calls by sourceIPAddress, userIdentity.arn
| sort calls desc
| limit 50
```

```
# Root account usage
fields eventTime, eventName, sourceIPAddress
| filter userIdentity.type = "Root"
| sort eventTime desc
```

```
# Failed authentication attempts
fields eventTime, eventName, userIdentity.arn, sourceIPAddress, errorCode
| filter errorCode = "AccessDenied" or errorCode = "InvalidClientTokenId"
| stats count(*) as failures by userIdentity.arn, sourceIPAddress
| sort failures desc
| limit 20
```

---

## Athena: Query CloudTrail at Scale

For large environments, query CloudTrail logs in S3 directly via Athena.

```sql
-- Create the CloudTrail table
CREATE EXTERNAL TABLE cloudtrail_logs (
  eventVersion STRING,
  userIdentity STRUCT<
    type:STRING,
    principalId:STRING,
    arn:STRING,
    accountId:STRING,
    userName:STRING
  >,
  eventTime STRING,
  eventSource STRING,
  eventName STRING,
  awsRegion STRING,
  sourceIPAddress STRING,
  userAgent STRING,
  errorCode STRING,
  errorMessage STRING,
  requestParameters STRING,
  responseElements STRING,
  requestId STRING,
  eventId STRING,
  resources ARRAY<STRUCT<ARN:STRING,accountId:STRING,type:STRING>>,
  eventType STRING,
  apiVersion STRING,
  readOnly STRING,
  recipientAccountId STRING,
  serviceEventDetails STRING,
  sharedEventId STRING,
  vpcEndpointId STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://cloudtrail-logs-ACCOUNT/AWSLogs/ACCOUNT/CloudTrail/';

-- Find all actions by a specific user last 30 days
SELECT eventTime, eventSource, eventName, sourceIPAddress, errorCode
FROM cloudtrail_logs
WHERE userIdentity.userName = 'suspect-user'
  AND eventTime > '2025-05-01'
ORDER BY eventTime DESC;

-- Find all console logins without MFA
SELECT eventTime, userIdentity.userName, sourceIPAddress,
  json_extract_scalar(responseElements, '$.ConsoleLogin') AS status
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND eventTime > '2025-05-01'
  AND NOT json_extract_scalar(additionalEventData, '$.MFAUsed') = 'Yes';
```

---

## References

- [CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [CloudTrail Log File Examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)
- [Querying CloudTrail with Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
