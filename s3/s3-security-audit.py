#!/usr/bin/env python3
"""
AWS S3 Security Audit
Checks S3 buckets for public access, ACLs, encryption, versioning, logging, MFA delete.

Requirements: AWS CLI configured with s3:List*, s3api:Get* permissions
Usage: python3 s3-security-audit.py [--profile PROFILE] [--region REGION] [--bucket BUCKET]
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def aws(args: list, profile: str = None, region: str = None) -> dict | list | None:
    cmd = ["aws"] + args + ["--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    if region:
        cmd += ["--region", region]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return json.loads(r.stdout)
        return None
    except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


class S3SecurityAudit:
    def __init__(self, profile=None, region=None, bucket_filter=None):
        self.profile = profile
        self.region = region
        self.bucket_filter = bucket_filter
        self.findings = []

    def _add(self, severity, check, bucket, detail, recommendation):
        self.findings.append({
            "severity": severity,
            "check": check,
            "bucket": bucket,
            "detail": detail,
            "recommendation": recommendation
        })

    def _pass(self, check, bucket):
        self.findings.append({
            "severity": "PASS",
            "check": check,
            "bucket": bucket,
            "detail": "Control satisfied",
            "recommendation": ""
        })

    # ── Public Access Block ────────────────────────────────────────────────────

    def check_public_access_block(self, bucket):
        data = aws(["s3api", "get-public-access-block", "--bucket", bucket],
                   self.profile, self.region)

        if not data:
            self._add("HIGH", "S3.01 - Public Access Block", bucket,
                      "Cannot retrieve public access block config (may be unset)",
                      "Enable all four Block Public Access settings")
            return

        cfg = data.get("PublicAccessBlockConfiguration", {})
        all_blocked = all([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])

        if not all_blocked:
            missing = [k for k, v in cfg.items() if not v]
            self._add("HIGH", "S3.01 - Public Access Block", bucket,
                      f"Not fully blocked. Disabled settings: {', '.join(missing)}",
                      "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets")
        else:
            self._pass("S3.01 - Public Access Block", bucket)

    # ── ACL ───────────────────────────────────────────────────────────────────

    def check_acl(self, bucket):
        data = aws(["s3api", "get-bucket-acl", "--bucket", bucket],
                   self.profile, self.region)
        if not data:
            return

        public_grantees = [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        ]

        for grant in data.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            permission = grant.get("Permission", "")
            if uri in public_grantees:
                self._add("CRITICAL", "S3.02 - Bucket ACL", bucket,
                          f"Public ACL grant: {uri} has {permission}",
                          "Remove public ACL grants. Use bucket policies with specific principals")
                return

        self._pass("S3.02 - Bucket ACL", bucket)

    # ── Bucket Policy ─────────────────────────────────────────────────────────

    def check_bucket_policy(self, bucket):
        data = aws(["s3api", "get-bucket-policy", "--bucket", bucket],
                   self.profile, self.region)

        if not data:
            return  # No policy is not inherently a finding

        try:
            policy = json.loads(data.get("Policy", "{}"))
        except json.JSONDecodeError:
            return

        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            effect = stmt.get("Effect", "")

            # Check for public Allow with wildcard principal
            is_public_principal = (principal == "*" or
                                   (isinstance(principal, dict) and
                                    principal.get("AWS") == "*"))

            if effect == "Allow" and is_public_principal:
                # Check if there are restricting conditions
                conditions = stmt.get("Condition", {})
                if not conditions:
                    self._add("CRITICAL", "S3.03 - Bucket Policy Public", bucket,
                              "Bucket policy allows public access (Principal: * with no conditions)",
                              "Add specific principal ARNs or add restrictive conditions")
                    return
                else:
                    self._add("MEDIUM", "S3.03 - Bucket Policy Public", bucket,
                              f"Bucket policy has public principal with conditions: {list(conditions.keys())}",
                              "Review conditions to ensure they adequately restrict access")
                    return

        self._pass("S3.03 - Bucket Policy Public", bucket)

    # ── Encryption ────────────────────────────────────────────────────────────

    def check_encryption(self, bucket):
        data = aws(["s3api", "get-bucket-encryption", "--bucket", bucket],
                   self.profile, self.region)

        if not data:
            self._add("HIGH", "S3.04 - Default Encryption", bucket,
                      "No default encryption configured",
                      "Enable SSE-S3 (AES256) as minimum; use SSE-KMS for sensitive data")
            return

        rules = data.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules:
            self._add("HIGH", "S3.04 - Default Encryption", bucket,
                      "Encryption configuration is empty",
                      "Enable SSE-S3 or SSE-KMS default encryption")
            return

        for rule in rules:
            sse = rule.get("ApplyServerSideEncryptionByDefault", {})
            algo = sse.get("SSEAlgorithm", "")
            kms_key = sse.get("KMSMasterKeyID", "")

            if algo == "aws:kms" and kms_key:
                self._pass("S3.04 - Default Encryption (SSE-KMS with CMK)", bucket)
            elif algo == "aws:kms":
                self._pass("S3.04 - Default Encryption (SSE-KMS with AWS-managed key)", bucket)
            elif algo == "AES256":
                self._pass("S3.04 - Default Encryption (SSE-S3)", bucket)
            else:
                self._add("HIGH", "S3.04 - Default Encryption", bucket,
                          f"Unknown encryption algorithm: {algo}",
                          "Use aws:kms with a customer-managed key for sensitive buckets")

    # ── Versioning ────────────────────────────────────────────────────────────

    def check_versioning(self, bucket):
        data = aws(["s3api", "get-bucket-versioning", "--bucket", bucket],
                   self.profile, self.region)

        if not data:
            self._add("MEDIUM", "S3.05 - Versioning", bucket,
                      "Cannot retrieve versioning status",
                      "Enable versioning for data protection and recovery")
            return

        status = data.get("Status", "")
        mfa_delete = data.get("MFADelete", "")

        if status != "Enabled":
            self._add("MEDIUM", "S3.05 - Versioning", bucket,
                      f"Versioning is {status or 'Disabled'}",
                      "Enable versioning to protect against accidental deletion and overwrites")
        else:
            if mfa_delete != "Enabled":
                self._add("LOW", "S3.05b - MFA Delete", bucket,
                          "Versioning enabled but MFA Delete is not enabled",
                          "Enable MFA Delete for critical buckets to require MFA for version deletion")
            else:
                self._pass("S3.05 - Versioning + MFA Delete", bucket)

    # ── Server Access Logging ─────────────────────────────────────────────────

    def check_logging(self, bucket):
        data = aws(["s3api", "get-bucket-logging", "--bucket", bucket],
                   self.profile, self.region)

        if not data:
            self._add("MEDIUM", "S3.06 - Access Logging", bucket,
                      "Cannot retrieve logging configuration",
                      "Enable server access logging to a separate logging bucket")
            return

        logging_cfg = data.get("LoggingEnabled", {})
        if not logging_cfg:
            self._add("MEDIUM", "S3.06 - Access Logging", bucket,
                      "Server access logging is disabled",
                      "Enable logging to a dedicated log bucket (e.g., s3-access-logs-ACCOUNT)")
        else:
            target = logging_cfg.get("TargetBucket", "unknown")
            self._pass(f"S3.06 - Access Logging → {target}", bucket)

    # ── SSL Enforcement via Bucket Policy ─────────────────────────────────────

    def check_ssl_policy(self, bucket):
        data = aws(["s3api", "get-bucket-policy", "--bucket", bucket],
                   self.profile, self.region)

        if not data:
            self._add("MEDIUM", "S3.07 - SSL Enforcement", bucket,
                      "No bucket policy — SSL transport not enforced",
                      "Add a bucket policy denying requests where aws:SecureTransport is false")
            return

        try:
            policy = json.loads(data.get("Policy", "{}"))
        except json.JSONDecodeError:
            return

        ssl_enforced = False
        for stmt in policy.get("Statement", []):
            conditions = stmt.get("Condition", {})
            deny = stmt.get("Effect") == "Deny"
            bool_cond = conditions.get("Bool", {})
            if deny and bool_cond.get("aws:SecureTransport") in ["false", False]:
                ssl_enforced = True
                break

        if not ssl_enforced:
            self._add("MEDIUM", "S3.07 - SSL Enforcement", bucket,
                      "Bucket policy does not deny non-SSL requests",
                      "Add: Deny Effect with Condition aws:SecureTransport = false")
        else:
            self._pass("S3.07 - SSL Enforcement", bucket)

    # ── Object Lock / Lifecycle ───────────────────────────────────────────────

    def check_object_lock(self, bucket):
        data = aws(["s3api", "get-object-lock-configuration", "--bucket", bucket],
                   self.profile, self.region)
        # Object lock is optional — only report if compliance/WORM is relevant
        # Not adding as finding, informational only

    # ── Main runner ───────────────────────────────────────────────────────────

    def audit_bucket(self, bucket):
        print(f"  Auditing: {bucket}")
        self.check_public_access_block(bucket)
        self.check_acl(bucket)
        self.check_bucket_policy(bucket)
        self.check_encryption(bucket)
        self.check_versioning(bucket)
        self.check_logging(bucket)
        self.check_ssl_policy(bucket)

    def run(self):
        print("[*] AWS S3 Security Audit\n")

        if self.bucket_filter:
            buckets = [self.bucket_filter]
        else:
            data = aws(["s3api", "list-buckets"], self.profile, self.region)
            if not data:
                print("[!] Cannot list buckets. Check credentials and permissions.")
                sys.exit(1)
            buckets = [b["Name"] for b in data.get("Buckets", [])]

        print(f"  Buckets to audit: {len(buckets)}\n")
        for bucket in buckets:
            self.audit_bucket(bucket)

        return self.findings

    def report(self):
        findings_only = [f for f in self.findings if f["severity"] != "PASS"]
        passes = [f for f in self.findings if f["severity"] == "PASS"]

        counts = {}
        for f in findings_only:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        print(f"\n{'='*60}")
        print(f"S3 SECURITY AUDIT RESULTS")
        print(f"{'='*60}")
        print(f"  Total buckets checked : {len(set(f['bucket'] for f in self.findings))}")
        print(f"  Total checks run      : {len(self.findings)}")
        print(f"  Passed                : {len(passes)}")
        print(f"  Findings              : {len(findings_only)}")
        print(f"    CRITICAL : {counts.get('CRITICAL', 0)}")
        print(f"    HIGH     : {counts.get('HIGH', 0)}")
        print(f"    MEDIUM   : {counts.get('MEDIUM', 0)}")
        print(f"    LOW      : {counts.get('LOW', 0)}")
        print(f"{'='*60}\n")

        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for f in sorted(findings_only, key=lambda x: sev_order.index(x.get("severity", "LOW"))):
            print(f"[{f['severity']}] {f['check']}")
            print(f"  Bucket         : {f['bucket']}")
            print(f"  Detail         : {f['detail']}")
            print(f"  Recommendation : {f['recommendation']}\n")

        # Save report
        Path("audit-reports").mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = Path(f"audit-reports/s3-security-audit-{ts}.json")
        out.write_text(json.dumps({
            "generated": datetime.now().isoformat(),
            "findings": findings_only,
            "passes": len(passes),
            "summary": counts
        }, indent=2))
        print(f"[+] Report saved: {out}")


def main():
    parser = argparse.ArgumentParser(description="AWS S3 Security Audit")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="eu-west-1", help="AWS region (default: eu-west-1)")
    parser.add_argument("--bucket", help="Audit a single bucket by name")
    args = parser.parse_args()

    audit = S3SecurityAudit(profile=args.profile, region=args.region, bucket_filter=args.bucket)
    audit.run()
    audit.report()


if __name__ == "__main__":
    main()
