#!/usr/bin/env python3
"""Fail-safe offline and optional AWS preflight checks for Chapter 0."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ALLOWED_ENVIRONMENTS = {"dev", "test"}
ACCOUNT_ID = re.compile(r"^\d{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
REQUIRED_SERVICES = {"bedrock", "iam", "kms", "secretsmanager", "cloudformation", "cloudtrail", "cloudwatch", "budgets"}
REQUIRED_TAGS = {"Application", "Environment", "Owner", "CostCenter", "DataClassification", "ManagedBy"}
REQUIRED_FORBIDDEN_DATA = {"real-phi", "real-pii", "production-secrets", "production-source-code", "live-patient-records"}
ALLOWED_TRAINING_DATA = {"synthetic-source-code", "synthetic-security-findings", "synthetic-patient-examples"}
SENSITIVE_KEY = re.compile(r"(secret|password|token|access.?key|private.?key|patient|medical.?record|ssn)", re.I)
SENSITIVE_VALUE = re.compile(r"(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\b\d{12}\b|arn:aws:|AKIA[0-9A-Z]{16})", re.I)
PLACEHOLDERS = {"", "replace-with-team-owner", "replace-me", "your-name"}
ACCOUNT_PLACEHOLDERS = {"000000000000"}


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("configuration root must be a JSON object")
    return value


def _check(name: str, passed: bool, detail: str) -> Check:
    return Check(name, "PASS" if passed else "FAIL", detail)


def validate_config(config: dict[str, Any]) -> list[Check]:
    checks: list[Check] = []
    environment = config.get("environment")
    checks.append(_check("non-production-environment", environment in ALLOWED_ENVIRONMENTS, f"environment={environment!r}; allowed={sorted(ALLOWED_ENVIRONMENTS)}"))

    region = config.get("awsRegion")
    checks.append(_check("aws-region-format", isinstance(region, str) and bool(REGION.fullmatch(region)), f"awsRegion={region!r}"))

    account = config.get("awsAccountId")
    account_ok = isinstance(account, str) and bool(ACCOUNT_ID.fullmatch(account)) and account not in ACCOUNT_PLACEHOLDERS
    checks.append(_check("aws-account-format", account_ok, "approved non-placeholder 12-digit account ID required; verify it independently before cloud use"))

    owner = config.get("owner")
    checks.append(_check("named-owner", isinstance(owner, str) and owner.strip().lower() not in PLACEHOLDERS, "accountable team owner must replace the placeholder"))

    budget = config.get("monthlyBudgetUsd")
    checks.append(_check("monthly-budget", isinstance(budget, (int, float)) and not isinstance(budget, bool) and 1 <= budget <= 10000, f"monthlyBudgetUsd={budget!r}; educational range=1..10000"))

    services = config.get("requiredServices")
    service_set = set(services) if isinstance(services, list) and all(isinstance(x, str) for x in services) else set()
    checks.append(_check("service-manifest", REQUIRED_SERVICES <= service_set, f"missing={sorted(REQUIRED_SERVICES - service_set)}"))

    forbidden = config.get("forbiddenData")
    forbidden_set = set(forbidden) if isinstance(forbidden, list) and all(isinstance(x, str) for x in forbidden) else set()
    checks.append(_check("healthcare-data-boundary", REQUIRED_FORBIDDEN_DATA <= forbidden_set, f"missing_denials={sorted(REQUIRED_FORBIDDEN_DATA - forbidden_set)}"))

    allowed = config.get("allowedData")
    allowed_set = set(allowed) if isinstance(allowed, list) and all(isinstance(x, str) for x in allowed) else set()
    allowed_ok = allowed_set == ALLOWED_TRAINING_DATA and not (allowed_set & REQUIRED_FORBIDDEN_DATA)
    checks.append(_check("synthetic-only-allowlist", allowed_ok, f"allowed={sorted(allowed_set)}; expected={sorted(ALLOWED_TRAINING_DATA)}"))

    tags = config.get("tags")
    tag_keys = set(tags) if isinstance(tags, dict) else set()
    tags_complete = REQUIRED_TAGS <= tag_keys
    tag_values_safe = isinstance(tags, dict) and all(
        isinstance(k, str) and isinstance(v, str)
        and not SENSITIVE_KEY.search(k)
        and not SENSITIVE_KEY.search(v)
        and not SENSITIVE_VALUE.search(v)
        for k, v in tags.items()
    )
    owner_bound = isinstance(tags, dict) and tags.get("Owner") == owner and owner not in PLACEHOLDERS
    classification_ok = isinstance(tags, dict) and tags.get("DataClassification") == "synthetic-training-only"
    checks.append(_check("safe-required-tags", tags_complete and tag_values_safe and owner_bound and classification_ok, f"missing={sorted(REQUIRED_TAGS - tag_keys)}; owner_bound={owner_bound}; synthetic_only={classification_ok}; values_safe={tag_values_safe}"))
    return checks


def _run_json(command: list[str]) -> Any:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def aws_checks(config: dict[str, Any]) -> list[Check]:
    if shutil.which("aws") is None:
        return [Check("aws-cli", "FAIL", "aws executable not found")]
    checks = [Check("aws-cli", "PASS", "aws executable found")]
    try:
        identity = _run_json(["aws", "sts", "get-caller-identity", "--output", "json"])
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        return checks + [Check("aws-session", "FAIL", f"configure an approved temporary session: {type(exc).__name__}")]
    expected = config.get("awsAccountId")
    actual = identity.get("Account")
    checks.append(_check("approved-aws-account", actual == expected, f"expected={expected}; actual={actual}"))
    configured_region = subprocess.run(["aws", "configure", "get", "region"], capture_output=True, text=True, check=False).stdout.strip()
    checks.append(_check("approved-aws-region", configured_region == config.get("awsRegion"), f"expected={config.get('awsRegion')}; configured={configured_region or 'unset'}"))
    return checks


def redacted_evidence(config: dict[str, Any], checks: list[Check]) -> dict[str, Any]:
    return {
        "schemaVersion": "1.0",
        "lab": "chapter-0",
        "organization": config.get("organization"),
        "environment": config.get("environment"),
        "awsRegion": config.get("awsRegion"),
        "accountFingerprint": f"ending-{str(config.get('awsAccountId', ''))[-4:]}",
        "dataClassification": "synthetic-training-only",
        # Evidence records only the decision, never command output or account IDs.
        "checks": [{"name": item.name, "status": item.status} for item in checks],
        "containsCredentials": False,
        "containsPhiOrPii": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--offline", action="store_true", help="make no AWS API calls")
    parser.add_argument("--evidence", type=Path, help="write a sanitized JSON evidence record")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL config: {exc}", file=sys.stderr)
        return 2
    checks = validate_config(config)
    if not args.offline:
        checks.extend(aws_checks(config))
    for item in checks:
        print(f"{item.status:4} {item.name}: {item.detail}")
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(redacted_evidence(config, checks), indent=2) + "\n", encoding="utf-8")
    return 1 if any(item.status == "FAIL" for item in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
