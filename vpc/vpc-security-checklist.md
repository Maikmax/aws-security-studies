# VPC Security Checklist

> Marcus Paula | IT Engineer — TikTok EMEA  
> Covers: Security Groups, NACLs, Flow Logs, VPC Endpoints, peering, public subnets

---

## Quick Reference

| Control | Severity | Check Command |
|---------|----------|--------------|
| No unrestricted SSH (0.0.0.0/0:22) | CRITICAL | `aws ec2 describe-security-groups` |
| No unrestricted RDP (0.0.0.0/0:3389) | CRITICAL | `aws ec2 describe-security-groups` |
| No unrestricted inbound on all ports | HIGH | `aws ec2 describe-security-groups` |
| VPC Flow Logs enabled | HIGH | `aws ec2 describe-flow-logs` |
| No default VPC in use | MEDIUM | `aws ec2 describe-vpcs` |
| Default SG has no rules | MEDIUM | `aws ec2 describe-security-groups` |
| S3/DynamoDB VPC Endpoints | MEDIUM | `aws ec2 describe-vpc-endpoints` |
| Public subnets properly tagged | LOW | Console/CLI |
| NACLs not overly permissive | LOW | `aws ec2 describe-network-acls` |

---

## 1. Security Groups vs NACLs

| Feature | Security Group | Network ACL |
|---------|---------------|-------------|
| Applies to | ENI / Instance | Subnet |
| State | Stateful (return traffic auto-allowed) | Stateless (must allow both directions) |
| Rules | Allow only | Allow and Deny |
| Rule evaluation | All rules evaluated | Rules evaluated in number order |
| Default | Deny all inbound, allow all outbound | Allow all in/out |
| Use case | Instance-level firewall | Subnet-level defense-in-depth |

---

## 2. Security Group Audit

### Find unrestricted inbound rules

```bash
# SSH open to the world (0.0.0.0/0 or ::/0)
aws ec2 describe-security-groups \
  --query "SecurityGroups[?contains(IpPermissions[].IpRanges[].CidrIp, '0.0.0.0/0') && contains(IpPermissions[].FromPort, \`22\`)].{ID:GroupId,Name:GroupName,VPC:VpcId}" \
  --output table

# RDP open to the world
aws ec2 describe-security-groups \
  --query "SecurityGroups[?contains(IpPermissions[].IpRanges[].CidrIp, '0.0.0.0/0') && contains(IpPermissions[].FromPort, \`3389\`)].{ID:GroupId,Name:GroupName,VPC:VpcId}" \
  --output table

# Any port 0-65535 open to 0.0.0.0/0
aws ec2 describe-security-groups --output json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for sg in data.get('SecurityGroups', []):
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        for cidr in rule.get('IpRanges', []):
            if cidr.get('CidrIp') in ['0.0.0.0/0', '::/0']:
                print(f\"OPEN: {sg['GroupId']} ({sg['GroupName']}) — {from_port}-{to_port} from {cidr['CidrIp']}\")
"
```

### Remediate: restrict SSH to specific CIDR

```bash
SG_ID="sg-xxxxxxxxxxxxxxxxx"
ALLOWED_CIDR="10.0.0.0/8"  # Replace with your VPN/office CIDR

# Remove the open rule
aws ec2 revoke-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Add restricted rule
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr "$ALLOWED_CIDR" \
  --tag-specifications "ResourceType=security-group-rule,Tags=[{Key=Purpose,Value=SSH-restricted}]"
```

### Default Security Group — should have no rules

```bash
# Find default SGs with rules
aws ec2 describe-security-groups \
  --filters Name=group-name,Values=default \
  --query "SecurityGroups[?IpPermissions != \`[]\` || IpPermissionsEgress[?IpProtocol!='-1' || IpRanges[0].CidrIp!='0.0.0.0/0']].{ID:GroupId,VPC:VpcId}" \
  --output table

# Remove all rules from default SG (do not delete — it cannot be deleted)
# Inbound
aws ec2 revoke-security-group-ingress \
  --group-id "sg-default-id" \
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids sg-default-id --query 'SecurityGroups[0].IpPermissions' --output json)"

# Outbound (except default allow-all which is needed unless you explicitly restrict)
```

---

## 3. VPC Flow Logs

Flow Logs capture IP traffic going to and from network interfaces. Essential for IR and network anomaly detection.

```bash
# Check if flow logs are enabled for each VPC
aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text | tr '\t' '\n' | while read vpc; do
  logs=$(aws ec2 describe-flow-logs \
    --filter "Name=resource-id,Values=$vpc" \
    --query 'FlowLogs[].{ID:FlowLogId,Status:FlowLogStatus,Dest:LogDestination}' \
    --output json)
  if [ "$logs" = "[]" ]; then
    echo "NO FLOW LOGS: $vpc"
  else
    echo "OK: $vpc — $(echo $logs | python3 -c 'import json,sys; [print(f["Status"], f["Dest"]) for f in json.load(sys.stdin)]')"
  fi
done

# Enable flow logs to CloudWatch Logs
aws ec2 create-flow-logs \
  --resource-ids vpc-xxxxxxxxxxxxxxxxx \
  --resource-type VPC \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::ACCOUNT:role/VPCFlowLogsRole

# Enable flow logs to S3
aws ec2 create-flow-logs \
  --resource-ids vpc-xxxxxxxxxxxxxxxxx \
  --resource-type VPC \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::vpc-flow-logs-ACCOUNT
```

### Analyze flow logs for suspicious traffic

```bash
# Top talkers (highest volume connections)
# Assuming logs delivered to S3, downloaded and decompressed:
awk 'NR>1 {print $4, $5, $6, $7, $13}' flow-log.txt | \
  sort | uniq -c | sort -rn | head -20

# Find rejected connections (potential port scan or blocked access)
awk '$14 == "REJECT" {print $4, $5, $6, $7}' flow-log.txt | \
  sort | uniq -c | sort -rn | head -20

# CloudWatch Logs Insights: top rejected sources
# (in /aws/vpc/flowlogs log group)
# fields srcAddr, dstPort, action
# | filter action = "REJECT"
# | stats count(*) as rejects by srcAddr
# | sort rejects desc
# | limit 20
```

---

## 4. Network ACLs

NACLs provide subnet-level stateless filtering. Use them as a second layer, not a replacement for Security Groups.

```bash
# List all NACLs and their rules
aws ec2 describe-network-acls \
  --query 'NetworkAcls[].{ID:NetworkAclId,VPC:VpcId,Default:IsDefault,Entries:Entries}' \
  --output json | python3 -c "
import json, sys
acls = json.load(sys.stdin)
for acl in acls:
    print(f\"ACL: {acl['ID']} (VPC: {acl['VPC']}, Default: {acl['Default']})\")
    for entry in sorted(acl['Entries'], key=lambda x: x['RuleNumber']):
        direction = 'INBOUND' if not entry['Egress'] else 'OUTBOUND'
        action = entry['RuleAction'].upper()
        cidr = entry.get('CidrBlock', entry.get('Ipv6CidrBlock', '?'))
        port_range = entry.get('PortRange', {})
        ports = f\"{port_range.get('From',0)}-{port_range.get('To',65535)}\" if port_range else 'ALL'
        print(f\"  [{entry['RuleNumber']:5d}] {direction:8s} {action:5s} {cidr:20s} ports {ports}\")
"
```

### Recommended NACL structure for a 3-tier VPC

```
Public Subnet NACL (web tier):
  Inbound:
    100 ALLOW TCP 0.0.0.0/0  80    (HTTP)
    110 ALLOW TCP 0.0.0.0/0  443   (HTTPS)
    120 ALLOW TCP 0.0.0.0/0  1024-65535  (ephemeral — return traffic)
    200 DENY  ALL 0.0.0.0/0  ALL
  Outbound:
    100 ALLOW TCP 0.0.0.0/0  80
    110 ALLOW TCP 0.0.0.0/0  443
    120 ALLOW TCP 10.0.0.0/8  ALL  (to app tier)
    130 ALLOW TCP 0.0.0.0/0  1024-65535  (ephemeral)
    200 DENY  ALL 0.0.0.0/0  ALL

App Subnet NACL (application tier):
  Inbound:
    100 ALLOW TCP 10.0.1.0/24  8080  (from web tier, app port)
    110 ALLOW TCP 10.0.0.0/8   22    (from bastion/VPN range)
    120 ALLOW TCP 0.0.0.0/0   1024-65535  (ephemeral)
    200 DENY  ALL 0.0.0.0/0   ALL
```

---

## 5. VPC Endpoints

Without VPC endpoints, traffic to AWS services (S3, DynamoDB, etc.) traverses the public internet. Endpoints keep traffic within the AWS network.

```bash
# Check existing endpoints
aws ec2 describe-vpc-endpoints \
  --query 'VpcEndpoints[].{ID:VpcEndpointId,VPC:VpcId,Service:ServiceName,Type:VpcEndpointType,State:State}' \
  --output table

# Create Gateway endpoint for S3 (free — recommended for all VPCs)
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxxxxxxxxxxxxxxxx \
  --service-name com.amazonaws.eu-west-1.s3 \
  --route-table-ids rtb-xxxxxxxxxxxxxxxxx

# Create Gateway endpoint for DynamoDB
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxxxxxxxxxxxxxxxx \
  --service-name com.amazonaws.eu-west-1.dynamodb \
  --route-table-ids rtb-xxxxxxxxxxxxxxxxx

# Create Interface endpoint for SSM (allows Session Manager without internet)
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxxxxxxxxxxxxxxxx \
  --service-name com.amazonaws.eu-west-1.ssm \
  --vpc-endpoint-type Interface \
  --subnet-ids subnet-xxxxxxxxxxxxxxxxx \
  --security-group-ids sg-xxxxxxxxxxxxxxxxx \
  --private-dns-enabled
```

### Endpoints to create for a fully private VPC (no internet required)

| Service | Endpoint Type | Cost | Priority |
|---------|--------------|------|----------|
| S3 | Gateway | Free | CRITICAL |
| DynamoDB | Gateway | Free | HIGH |
| SSM | Interface | Paid | HIGH (Session Manager) |
| SSM Messages | Interface | Paid | HIGH |
| EC2 Messages | Interface | Paid | HIGH |
| Secrets Manager | Interface | Paid | HIGH |
| KMS | Interface | Paid | MEDIUM |
| ECR API | Interface | Paid | MEDIUM (if using containers) |
| ECR DKR | Interface | Paid | MEDIUM |
| CloudWatch Logs | Interface | Paid | MEDIUM |
| STS | Interface | Paid | MEDIUM |

---

## 6. Default VPC

The default VPC is created automatically in each region and is not hardened. Do not use it for workloads.

```bash
# List all default VPCs across regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  default=$(aws ec2 describe-vpcs \
    --region "$region" \
    --filters Name=isDefault,Values=true \
    --query 'Vpcs[].VpcId' \
    --output text 2>/dev/null)
  if [ -n "$default" ]; then
    echo "$region: Default VPC exists — $default"
  fi
done

# Delete default VPC in a region (if not in use)
# WARNING: verify no resources are attached first
VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
# Delete internet gateway, subnets, then the VPC itself
IGW=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query 'InternetGateways[0].InternetGatewayId' --output text)
aws ec2 detach-internet-gateway --internet-gateway-id "$IGW" --vpc-id "$VPC_ID"
aws ec2 delete-internet-gateway --internet-gateway-id "$IGW"
# ... then delete subnets and VPC
```

---

## References

- [Security Groups vs NACLs](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [VPC Endpoints](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints.html)
- [CIS AWS Benchmark — VPC Section](https://www.cisecurity.org/benchmark/amazon_web_services)
