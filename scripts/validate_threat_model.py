#!/usr/bin/env python3
"""Validate the Chapter 1 threat model without calling AWS."""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FORBIDDEN = {"real-phi", "real-pii", "production-secrets", "production-source-code", "live-patient-records"}
OBJECTIVES = {"no-real-phi-or-pii", "no-production-secrets", "no-self-approval", "no-direct-production-deployment", "sanitized-auditability"}
STRIDE = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
SENSITIVE = re.compile(r"(?:\b\d{3}-\d{2}-\d{4}\b|\bAKIA[0-9A-Z]{16}\b|bearer\s+[a-z0-9._-]+|patient\s*name\s*[:=]\s*[A-Z][a-z]+\s+[A-Z][a-z]+)", re.I)

@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str

def check(name: str, passed: bool, detail: str) -> Check:
    return Check(name, "PASS" if passed else "FAIL", detail)

def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    return value

def unique_ids(items: Any) -> tuple[bool, set[str]]:
    if not isinstance(items, list) or not items:
        return False, set()
    ids = [x.get("id") for x in items if isinstance(x, dict)]
    return len(ids) == len(items) and all(isinstance(x, str) and x for x in ids) and len(ids) == len(set(ids)), set(ids)

def validate(m: dict[str, Any]) -> list[Check]:
    out: list[Check] = []
    out.append(check("identity", m.get("chapter") == 1 and m.get("environment") == "non-production", "Chapter 1 must remain non-production"))
    policy = m.get("dataPolicy", {})
    forbidden_values = policy.get("forbidden", []) if isinstance(policy, dict) else []
    forbidden = set(forbidden_values) if isinstance(forbidden_values, list) and all(isinstance(x, str) for x in forbidden_values) else set()
    minimum_necessary = isinstance(policy, dict) and policy.get("minimumNecessary") is True
    out.append(check("data-boundary", FORBIDDEN <= forbidden and minimum_necessary, f"missing={sorted(FORBIDDEN-forbidden)}"))
    guardrails_layered = isinstance(policy, dict) and policy.get("bedrockGuardrailsAreOnlyControl") is False
    out.append(check("layered-protection", guardrails_layered, "Guardrails cannot be the only sensitive-data control"))

    assets_ok, asset_ids = unique_ids(m.get("assets"))
    asset_fields = assets_ok and all(x.get("name") and x.get("classification") and x.get("owner") for x in m["assets"])
    out.append(check("owned-assets", bool(asset_fields), "Every uniquely identified asset needs classification and owner"))
    comp_ok, component_ids = unique_ids(m.get("components"))
    out.append(check("components", comp_ok and len(component_ids) >= 5, "At least five uniquely identified components required"))

    actors_ok, _ = unique_ids(m.get("actors"))
    actor_complete = actors_ok and all(x.get("name") and x.get("trust") for x in m["actors"])
    out.append(check("actors", bool(actor_complete), "Every actor needs a unique ID, name, and trust level"))

    boundaries_ok, boundary_ids = unique_ids(m.get("trustBoundaries"))
    boundary_complete = boundaries_ok and all(x.get("from") in component_ids and x.get("to") in component_ids and len(x.get("requiredChecks", [])) >= 2 for x in m["trustBoundaries"])
    out.append(check("trust-boundaries", boundary_complete, "Every boundary needs known endpoints and at least two checks"))

    tests_ok, test_ids = unique_ids(m.get("abuseTests"))
    safe_tests = tests_ok and all(x.get("payloadClass") and x.get("expected") and x.get("prohibitedSideEffects") for x in m["abuseTests"])
    out.append(check("safe-abuse-tests", bool(safe_tests) and len(test_ids) >= 6, "Each harmless test needs an expected result and prohibited side effects"))

    threats_ok, threat_ids = unique_ids(m.get("threats"))
    references_ok = threats_ok and all(set(t.get("assetIds", [])) <= asset_ids and set(t.get("boundaryIds", [])) <= boundary_ids and set(t.get("testIds", [])) <= test_ids for t in m["threats"])
    out.append(check("threat-references", references_ok, "Threat references must resolve"))
    covered = {t.get("stride") for t in m.get("threats", []) if isinstance(t, dict)}
    out.append(check("stride-coverage", STRIDE <= covered, f"missing={sorted(STRIDE-covered)}"))
    actionable = threats_ok and all(t.get("scenario") and t.get("owner") and t.get("likelihood") in {"low", "medium", "high"} and t.get("impact") in {"low", "medium", "high", "critical"} and len(t.get("mitigations", [])) >= 2 and t.get("testIds") for t in m["threats"])
    out.append(check("actionable-threats", bool(actionable), "Each threat needs owner, rating, mitigations, and tests"))
    linked_tests = {i for t in m.get("threats", []) if isinstance(t, dict) for i in t.get("testIds", [])}
    out.append(check("test-coverage", tests_ok and linked_tests == test_ids, f"unlinked={sorted(test_ids-linked_tests)}"))
    objectives = set(m.get("securityObjectives", []))
    out.append(check("security-objectives", OBJECTIVES <= objectives, f"missing={sorted(OBJECTIVES-objectives)}"))
    residual_ok, _ = unique_ids(m.get("residualRisks"))
    residual_complete = residual_ok and all(x.get("statement") and x.get("owner") and x.get("treatment") for x in m["residualRisks"])
    out.append(check("residual-risk", bool(residual_complete), "Residual risks need owner and treatment"))
    serialized = json.dumps(m)
    out.append(check("no-sensitive-values", SENSITIVE.search(serialized) is None, "Manifest must contain no real-looking sensitive value"))
    return out

def evidence(m: dict[str, Any], checks: list[Check]) -> dict[str, Any]:
    # Store decisions only. Check details are useful on screen but can echo
    # manifest-derived values and therefore do not belong in durable evidence.
    return {"schemaVersion": "1.0", "lab": "chapter-1", "system": m.get("system"), "environment": m.get("environment"), "summary": {"assets": len(m.get("assets", [])), "boundaries": len(m.get("trustBoundaries", [])), "threats": len(m.get("threats", [])), "abuseTests": len(m.get("abuseTests", []))}, "checks": [{"name": x.name, "status": x.status} for x in checks], "containsPhiOrPii": False, "containsCredentials": False, "awsCallsMade": False}

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--evidence", type=Path)
    args = p.parse_args()
    try:
        manifest = load(args.manifest)
        checks = validate(manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL manifest: {exc}", file=sys.stderr)
        return 2
    for item in checks:
        print(f"{item.status:4} {item.name}: {item.detail}")
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence(manifest, checks), indent=2) + "\n", encoding="utf-8")
    return 1 if any(x.status == "FAIL" for x in checks) else 0

if __name__ == "__main__":
    raise SystemExit(main())
