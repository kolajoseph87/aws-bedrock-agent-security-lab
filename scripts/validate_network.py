#!/usr/bin/env python3
"""Offline validator for Chapter 2's AWS network-design contract."""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path


REQUIRED_ENDPOINTS = {"bedrock-runtime", "bedrock-agent-runtime", "kms", "secretsmanager", "logs", "sts", "s3"}
SENSITIVE_KEY = re.compile(r"(?:access.?key|secret|token|password|patient|medical.?record|mrn|diagnosis|ssn)", re.I)
SENSITIVE_VALUE = re.compile(r"(?:\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b|arn:aws:|bearer\s+[a-z0-9._-]+|\b\d{3}-\d{2}-\d{4}\b)", re.I)


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _object_list(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _contains_sensitive_key(value):
    if isinstance(value, dict):
        return any(SENSITIVE_KEY.search(str(key)) or _contains_sensitive_key(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def validate(data):
    checks = []

    def check(name, condition, detail):
        checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})

    if not isinstance(data, dict):
        check("manifest object", False, "Manifest root must be an object.")
        return checks

    network = _mapping(data.get("network"))
    healthcare = _mapping(data.get("healthcare_data"))
    authorization = _mapping(data.get("authorization"))
    egress = _mapping(data.get("egress"))
    endpoints = _object_list(data.get("private_endpoints"))
    subnets = _object_list(network.get("subnets"))

    synthetic_scope = (
        data.get("environment") != "production"
        and data.get("data_classification") == "synthetic-only"
        and healthcare.get("synthetic_only") is True
        and healthcare.get("real_phi_allowed") is False
        and healthcare.get("real_pii_allowed") is False
        and healthcare.get("production_source_allowed") is False
    )
    check("non-production synthetic scope", synthetic_scope, "Only synthetic data is permitted in a non-production lab.")

    try:
        vpc = ipaddress.ip_network(network.get("vpc_cidr", "invalid"), strict=True)
        nets = [ipaddress.ip_network(subnet["cidr"], strict=True) for subnet in subnets]
        names = [subnet.get("name") for subnet in subnets]
        valid_ranges = all(net.subnet_of(vpc) for net in nets)
        no_overlap = all(not left.overlaps(right) for index, left in enumerate(nets) for right in nets[index + 1:])
        unique_subnets = len(names) == len(set(names)) and len(nets) == len(set(nets)) and all(isinstance(name, str) and name for name in names)
    except (TypeError, ValueError, KeyError):
        valid_ranges = no_overlap = unique_subnets = False
    check("valid non-overlapping address plan", valid_ranges and no_overlap and unique_subnets and len(subnets) >= 6, "Every uniquely named subnet must be inside the VPC and separate.")

    required_purposes = {"secure-coding-agent", "isolated-code-worker", "interface-endpoints"}
    purposes = {subnet.get("purpose") for subnet in subnets}
    private_subnets = bool(subnets) and all(subnet.get("public_ip_on_launch") is False for subnet in subnets)
    multi_az = all(len({subnet.get("az_index") for subnet in subnets if subnet.get("purpose") == purpose}) >= 2 for purpose in required_purposes)
    check("separated private trust zones", required_purposes.issubset(purposes) and private_subnets and multi_az, "Agent, worker, and endpoint tiers use private subnets in at least two AZs.")

    no_internet = network.get("internet_gateway_attached") is False and network.get("nat_gateway_deployed") is False and egress.get("default_internet_route") is False and egress.get("direct_worker_internet") == "deny"
    check("no default internet path", no_internet, "Workers have no direct Internet route.")

    service_names = [endpoint.get("service") for endpoint in endpoints]
    services = set(service_names)
    unique_services = len(service_names) == len(services) and all(isinstance(name, str) and name for name in service_names)
    private_dns = all(endpoint.get("private_dns") is True for endpoint in endpoints if endpoint.get("type") == "interface")
    check("required private service paths", REQUIRED_ENDPOINTS.issubset(services) and private_dns and unique_services, "Unique required AWS service endpoints and private DNS are declared.")

    policies = bool(endpoints) and all(endpoint.get("endpoint_policy") not in (None, "", "full-access") for endpoint in endpoints)
    check("restricted endpoint policies", policies, "Every endpoint requires a restricted endpoint policy.")

    security_groups = _mapping(data.get("security_groups"))
    serialized_groups = json.dumps(security_groups)
    no_world = "0.0.0.0/0" not in serialized_groups and "::/0" not in serialized_groups
    check("least-privilege security groups", set(security_groups) == {"agent", "worker", "endpoint"} and no_world, "Security groups contain no world-open rule.")

    authorization_ok = authorization.get("private_network_is_trust") is False and all(authorization.get(key) is True for key in ("iam_required", "endpoint_policy_required", "runtime_exact_action_check_required"))
    check("network is not authorization", authorization_ok, "IAM and exact runtime authorization remain mandatory.")

    observability = _mapping(data.get("observability"))
    safe_evidence = observability.get("vpc_flow_logs_required_for_live_environment") is True and observability.get("dns_query_logging_required_for_live_environment") is True and observability.get("redaction_and_access_control_required") is True and healthcare.get("sensitive_data_in_flow_logs") is False
    check("privacy-safe network evidence", safe_evidence, "Live network evidence must be enabled, restricted, and sanitized.")

    attacks = _object_list(data.get("safe_attacks"))
    attack_ids = [attack.get("id") for attack in attacks]
    allowed_results = {"denied", "runtime_policy_denied", "iam_or_endpoint_policy_denied", "denied_and_sanitized"}
    safe_attacks = len(attacks) >= 6 and len(attack_ids) == len(set(attack_ids)) and all(isinstance(identifier, str) and identifier for identifier in attack_ids) and all(attack.get("prohibited_side_effects") == 0 and attack.get("expected") in allowed_results for attack in attacks)
    check("safe negative tests", safe_attacks, "Attacks must have unique IDs, exact denial outcomes, and zero prohibited side effects.")

    serialized = json.dumps(data)
    safe_fields = not _contains_sensitive_key(data) and SENSITIVE_VALUE.search(serialized) is None
    check("no sensitive fields", safe_fields, "Manifest must not contain credential, healthcare-identifier, or real-looking secret fields.")

    lowered = serialized.lower()
    limitations = data.get("limitations") if isinstance(data.get("limitations"), list) else []
    honest = len(limitations) >= 4 and "does not authorize" in lowered and "not content-aware" in lowered
    check("honest capability claims", honest, "Limitations distinguish networking, authorization, and content controls.")
    return checks


def sanitized_evidence(checks):
    return {
        "chapter": 2,
        "mode": "offline",
        "aws_calls": 0,
        "resources_created": 0,
        "checks": [{"name": item["name"], "status": item["status"]} for item in checks],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: manifest could not be loaded: {exc}", file=sys.stderr)
        return 2
    checks = validate(data)
    out = Path(args.evidence)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sanitized_evidence(checks), indent=2) + "\n", encoding="utf-8")
    for item in checks:
        print(f'{item["status"]}: {item["name"]}')
    if any(item["status"] == "FAIL" for item in checks):
        return 1
    print(f"{len(checks)} Chapter 2 network checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
