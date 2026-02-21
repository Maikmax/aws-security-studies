#!/usr/bin/env python3
"""
AWS IAM Audit — Security Posture Check
Evaluates IAM configuration against CIS AWS Foundations Benchmark v1.4

Requirements: AWS CLI configured with read-only IAM permissions
Usage: python3 aws-iam-audit.py [--profile PROFILE] [--region REGION]
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path


def aws(args: list, profile: str = None, region: str = None) -> dict | list | None:
    cmd = ["aws"] + args + ["--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    if region:
        cmd += ["--region", region]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return json.loads(r.stdout) if r.returncode == 0 else None
    except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


class IAMAudit:
    def __init__(self, profile=None, region=None):
        self.profile = profile
        self.region = region
        self.findings = []

    def _add(self, severity, check, resource, detail, recommendation):
        self.findings.append({
            "severity": severity,
            "check": check,
            "resource": resource,
            "detail": detail,
            "recommendation": recommendation
        })

    # CIS 1.1 — Root account MFA
    def check_root_mfa(self):
        data = aws(["iam", "get-account-summary"], self.profile, self.region)
        if not data:
            return
        if data.get("SummaryMap", {}).get("AccountMFAEnabled", 0) == 0:
            self._add("CRITICAL", "CIS 1.1 - Root MFA", "root",
                      "Root account MFA is not enabled",
                      "Enable MFA on root account immediately")

    # CIS 1.4 — Root access keys
    def check_root_access_keys(self):
        data = aws(["iam", "get-account-summary"], self.profile, self.region)
        if not data:
            return
        if data.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0) > 0:
            self._add("CRITICAL", "CIS 1.4 - Root Access Keys", "root",
                      "Active access keys exist for root account",
                      "Delete all root account access keys")

    # CIS 1.5-1.11 — Password policy
    def check_password_policy(self):
        data = aws(["iam", "get-account-password-policy"], self.profile, self.region)
        if not data:
            self._add("HIGH", "CIS 1.5 - Password Policy", "account",
                      "No password policy configured",
                      "Configure a strong password policy")
            return

        p = data.get("PasswordPolicy", {})
        rules = [
            ("MinimumPasswordLength", 14, ">=", "CIS 1.9 - Min password length 14"),
            ("RequireUppercaseCharacters", True, "==", "CIS 1.5 - Require uppercase"),
            ("RequireLowercaseCharacters", True, "==", "CIS 1.6 - Require lowercase"),
            ("RequireNumbers", True, "==", "CIS 1.7 - Require numbers"),
            ("RequireSymbols", True, "==", "CIS 1.8 - Require symbols"),
            ("MaxPasswordAge", 90, "<=", "CIS 1.10 - Password expiry <= 90 days"),
            ("PasswordReusePrevention", 24, ">=", "CIS 1.11 - Password reuse prevention 24"),
        ]

        for key, threshold, op, label in rules:
            val = p.get(key)
            fail = False
            if op == ">=" and (val is None or val < threshold):
                fail = True
            elif op == "<=" and (val is None or val > threshold):
                fail = True
            elif op == "==" and val is not True:
                fail = True

            if fail:
                self._add("MEDIUM", label, "account",
                          f"{key} = {val} (expected {op} {threshold})",
                          f"Set {key} to meet CIS benchmark")

    # CIS 1.2 — No active access keys for root; CIS 1.16 — No full admin policies
    def check_iam_users(self):
        data = aws(["iam", "list-users"], self.profile, self.region)
        if not data:
            return

        for user in data.get("Users", []):
            uname = user["UserName"]

            # MFA check for console users
            mfa = aws(["iam", "list-mfa-devices", "--user-name", uname],
                      self.profile, self.region)
            login = aws(["iam", "get-login-profile", "--user-name", uname],
                        self.profile, self.region)

            if login and mfa and len(mfa.get("MFADevices", [])) == 0:
                self._add("HIGH", "CIS 1.2 - User MFA", uname,
                          "Console access enabled with no MFA",
                          "Enable MFA or remove console access")

            # Stale access keys (> 90 days)
            keys = aws(["iam", "list-access-keys", "--user-name", uname],
                       self.profile, self.region)
            if keys:
                for key in keys.get("AccessKeyMetadata", []):
                    if key["Status"] == "Active":
                        age = (datetime.now() -
                               datetime.strptime(key["CreateDate"][:10], "%Y-%m-%d")).days
                        if age > 90:
                            self._add("MEDIUM", "CIS 1.13 - Stale Access Key", uname,
                                      f"Key {key['AccessKeyId']} is {age} days old",
                                      "Rotate access keys every 90 days")

            # Full admin policy attached directly
            attached = aws(["iam", "list-attached-user-policies", "--user-name", uname],
                           self.profile, self.region)
            if attached:
                for p in attached.get("AttachedPolicies", []):
                    if p["PolicyName"] == "AdministratorAccess":
                        self._add("HIGH", "CIS 1.16 - Admin Policy on User", uname,
                                  "AdministratorAccess attached directly to user",
                                  "Use IAM roles with least privilege instead")

    # S3 public access check
    def check_s3_public_access(self):
        buckets = aws(["s3api", "list-buckets"], self.profile, self.region)
        if not buckets:
            return

        for bucket in buckets.get("Buckets", []):
            name = bucket["Name"]
            block = aws(["s3api", "get-public-access-block", "--bucket", name],
                        self.profile, self.region)
            if block:
                config = block.get("PublicAccessBlockConfiguration", {})
                if not all([
                    config.get("BlockPublicAcls"),
                    config.get("IgnorePublicAcls"),
                    config.get("BlockPublicPolicy"),
                    config.get("RestrictPublicBuckets"),
                ]):
                    self._add("HIGH", "S3 Public Access Block", name,
                              "S3 bucket does not block all public access",
                              "Enable all four S3 Block Public Access settings")

    def run(self):
        print("[*] AWS IAM Security Audit\n")
        checks = [
            ("Root MFA", self.check_root_mfa),
            ("Root Access Keys", self.check_root_access_keys),
            ("Password Policy", self.check_password_policy),
            ("IAM Users", self.check_iam_users),
            ("S3 Public Access", self.check_s3_public_access),
        ]

        for name, fn in checks:
            print(f"  Checking: {name}...")
            fn()

        return self.findings

    def report(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        print(f"\n{'='*50}")
        print(f"FINDINGS: {len(self.findings)}")
        print(f"  CRITICAL : {counts['CRITICAL']}")
        print(f"  HIGH     : {counts['HIGH']}")
        print(f"  MEDIUM   : {counts['MEDIUM']}")
        print(f"{'='*50}\n")

        for f in sorted(self.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"])):
            print(f"[{f['severity']}] {f['check']}")
            print(f"  Resource       : {f['resource']}")
            print(f"  Detail         : {f['detail']}")
            print(f"  Recommendation : {f['recommendation']}\n")

        # Save JSON
        Path("audit-reports").mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = Path(f"audit-reports/aws-iam-audit-{ts}.json")
        out.write_text(json.dumps({
            "generated": datetime.now().isoformat(),
            "findings": self.findings,
            "summary": counts
        }, indent=2))
        print(f"[+] Report: {out}")


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Audit")
    parser.add_argument("--profile", help="AWS CLI profile")
    parser.add_argument("--region", default="eu-west-1", help="AWS region (default: eu-west-1)")
    args = parser.parse_args()

    audit = IAMAudit(profile=args.profile, region=args.region)
    audit.run()
    audit.report()


if __name__ == "__main__":
    main()
