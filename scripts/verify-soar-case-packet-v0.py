#!/usr/bin/env python3
"""Verify the SOAR case packet v0 sample stays deterministic and claim-bounded."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATH = ROOT / "contracts" / "examples" / "soar-case-packet-v0.sample.json"
SCHEMA_PATH = ROOT / "contracts" / "schemas" / "soar-case-packet-v0.schema.json"

EXPECTED = {
    "packet_type": "soar_style_analyst_support_case_packet",
    "contract_version": "soar-case-packet-v0",
    "workflow_model": "deterministic_analyst_support_only",
    "claim_ceiling": "SOAR_STYLE_ANALYST_SUPPORT_CONTRACT_WITH_DETERMINISTIC_VALIDATION",
    "human_review_required": True,
    "ai_decided_disposition": False,
    "recommended_disposition": None,
    "public_safe": False,
}

REQUIRED_BLOCKED_ACTIONS = {
    "contain host",
    "close case",
    "suppress detection",
    "disable account",
    "isolate endpoint",
    "declare compromise",
    "mark malicious",
    "approve public proof",
}

REQUIRED_UNSUPPORTED_CLAIMS = {
    "live Torq",
    "live SOAR",
    "production SOC",
    "production response automation",
    "runtime-active proof",
    "signal-observed public proof",
    "evidence-linked public proof",
    "public-safe proof",
    "autonomous SOC",
    "AI-approved disposition",
    "analyst-approved disposition",
    "containment execution",
    "closure execution",
    "suppression execution",
    "bank-grade deployment",
    "SOCaaS availability",
}

PROMOTIONAL_PATTERNS = [
    r"\blive\s+torq\b",
    r"\blive\s+soar\b",
    r"\bproduction\s+soc\b",
    r"\bproduction\s+response\s+automation\b",
    r"\bruntime[-\s]+active\s+proof\b",
    r"\bsignal[-\s]+observed\s+public\s+proof\b",
    r"\bevidence[-\s]+linked\s+public\s+proof\b",
    r"\bpublic[-\s]+safe\s+proof\b",
    r"\bautonomous\s+soc\b",
    r"\bai[-\s]+approved\s+disposition\b",
    r"\banalyst[-\s]+approved\s+disposition\b",
    r"\bcontainment\s+execut(?:ed|ion)\b",
    r"\bclosure\s+execut(?:ed|ion)\b",
    r"\bsuppression\s+execut(?:ed|ion)\b",
    r"\bbank[-\s]+grade\s+deployment\b",
    r"\bsocaas\b",
]

EXECUTED_ACTION_PATTERNS = [
    r"\bcontained\s+host\b",
    r"\bhost\s+contained\b",
    r"\bcase\s+closed\b",
    r"\bclosed\s+case\b",
    r"\bdetection\s+suppressed\b",
    r"\bsuppressed\s+detection\b",
    r"\baccount\s+disabled\b",
    r"\bdisabled\s+account\b",
    r"\bendpoint\s+isolated\b",
    r"\bisolated\s+endpoint\b",
    r"\bcompromise\s+declared\b",
    r"\bdeclared\s+compromise\b",
    r"\bmarked\s+malicious\b",
    r"\bpublic\s+proof\s+approved\b",
]

UNSUPPORTED_DISPOSITION_PATTERNS = [
    r"\bmalicious\s+confirmed\b",
    r"\bconfirmed\s+malicious\b",
    r"\bcompromise\s+confirmed\b",
    r"\bconfirmed\s+compromise\b",
    r"\bmark\s+benign\b",
    r"\bmark\s+malicious\b",
    r"\brecommended\s+disposition\s*:\s*(?!null)",
    r"\bai\s+decided\b",
    r"\bai\s+approved\b",
    r"\banalyst\s+approved\b",
]

PRIVATE_LEAK_PATTERNS = [
    r"\b[A-Za-z]:[\\/]",
    r"\b(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    r"(?i)\b(secret|password|token|api[_-]?key|credential|authorization|set-cookie)\b",
    r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
]

PRIVATE_OR_RECRUITER_TERMS = [
    r"(?i)\brecruiter\b",
    r"(?i)\bhiring\s+manager\b",
    r"(?i)\binterview\b",
    r"(?i)\boffer\b",
    r"(?i)\bprivate\s+opportunity\b",
    r"(?i)\binternal\s+only\b",
    r"(?i)\bconfidential\b",
]

ALLOWED_NEGATIVE_PATHS = {
    ("claim_boundary", "not_supported"),
    ("does_not_prove",),
}


def fail(message: str) -> None:
    print(f"SOAR_CASE_PACKET_V0=fail: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")
    if not isinstance(data, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return data


def validate_schema_if_possible(sample: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        import jsonschema  # type: ignore
    except Exception as exc:
        print(f"SCHEMA_VALIDATOR=jsonschema_unavailable_using_stdlib_subset: {exc}")
        validate_schema_subset(sample, schema)
        return

    try:
        jsonschema.Draft202012Validator(schema).validate(sample)
    except Exception as exc:
        fail(f"schema validation failed: {exc}")


def validate_schema_subset(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
    root_schema: dict[str, Any] | None = None,
) -> None:
    if root_schema is None:
        root_schema = schema

    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        if "null" in schema_type and value is None:
            return
        schema_type = next((item for item in schema_type if item != "null"), schema_type[0])

    if schema_type == "object":
        if not isinstance(value, dict):
            fail(f"schema validation failed: {path} must be object")
        required = schema.get("required", [])
        if not isinstance(required, list):
            fail(f"schema validation failed: {path}.required must be a list")
        for key in required:
            if key not in value:
                fail(f"schema validation failed: {path}.{key} is required")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            fail(f"schema validation failed: {path}.properties must be an object")
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                fail(f"schema validation failed: {path} has extra keys: {', '.join(extra)}")
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, dict):
                child_schema = resolve_ref(child_schema, root_schema)
                validate_schema_subset(value[key], child_schema, f"{path}.{key}", root_schema)
    elif schema_type == "array":
        if not isinstance(value, list):
            fail(f"schema validation failed: {path} must be array")
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(value) < min_items:
            fail(f"schema validation failed: {path} must contain at least {min_items} items")
        if schema.get("uniqueItems") is True and len(value) != len({json.dumps(item, sort_keys=True) for item in value}):
            fail(f"schema validation failed: {path} must contain unique items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            item_schema = resolve_ref(item_schema, root_schema)
            for index, item in enumerate(value):
                validate_schema_subset(item, item_schema, f"{path}[{index}]", root_schema)
    elif schema_type == "string":
        if not isinstance(value, str):
            fail(f"schema validation failed: {path} must be string")
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(value) < min_length:
            fail(f"schema validation failed: {path} must not be empty")
    elif schema_type == "boolean" and not isinstance(value, bool):
        fail(f"schema validation failed: {path} must be boolean")
    elif schema_type == "integer" and not isinstance(value, int):
        fail(f"schema validation failed: {path} must be integer")
    elif schema_type == "null" and value is not None:
        fail(f"schema validation failed: {path} must be null")

    if "const" in schema and value != schema["const"]:
        fail(f"schema validation failed: {path} expected {schema['const']!r}, got {value!r}")
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        fail(f"schema validation failed: {path} is not an allowed value: {value!r}")
    minimum = schema.get("minimum")
    if isinstance(minimum, int) and isinstance(value, int) and value < minimum:
        fail(f"schema validation failed: {path} must be at least {minimum}")


def resolve_ref(schema: dict[str, Any], root_schema: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if not isinstance(ref, str):
        return schema
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        fail(f"schema validation failed: unsupported $ref {ref!r}")
    defs = root_schema.get("$defs")
    if not isinstance(defs, dict):
        fail("schema validation failed: missing $defs")
    name = ref[len(prefix):]
    target = defs.get(name)
    if not isinstance(target, dict):
        fail(f"schema validation failed: missing $defs.{name}")
    return target


def require_expected_values(sample: dict[str, Any]) -> None:
    for key, expected in EXPECTED.items():
        actual = sample.get(key)
        if actual != expected:
            fail(f"{key} expected {expected!r}, got {actual!r}")

    boundary = sample.get("claim_boundary")
    if not isinstance(boundary, dict):
        fail("claim_boundary must be an object")
    if boundary.get("supported_claim") != "SOAR-style analyst-support case packet contract with deterministic validation.":
        fail("claim_boundary.supported_claim is missing or unsupported")
    if boundary.get("public_claim_allowed") is not False:
        fail("claim_boundary.public_claim_allowed must be false")


def require_blocked_actions(sample: dict[str, Any]) -> None:
    blocked = sample.get("blocked_actions")
    if not isinstance(blocked, list):
        fail("blocked_actions must be a list")
    missing = sorted(REQUIRED_BLOCKED_ACTIONS - set(blocked))
    if missing:
        fail(f"missing blocked_actions entries: {', '.join(missing)}")

    gates = sample.get("response_gates")
    if not isinstance(gates, dict):
        fail("response_gates must be an object")
    for gate_name, gate in gates.items():
        if not isinstance(gate, dict):
            fail(f"response_gates.{gate_name} must be an object")
        if gate.get("status") != "blocked":
            fail(f"response_gates.{gate_name}.status must be blocked")
        if gate.get("requires_human_approval") is not True:
            fail(f"response_gates.{gate_name}.requires_human_approval must be true")
        if gate.get("executed") is not False:
            fail(f"response_gates.{gate_name}.executed must be false")


def require_unsupported_claim_inventory(sample: dict[str, Any]) -> None:
    boundary = sample.get("claim_boundary")
    if not isinstance(boundary, dict):
        fail("claim_boundary must be an object")
    not_supported = boundary.get("not_supported")
    does_not_prove = sample.get("does_not_prove")
    if not isinstance(not_supported, list):
        fail("claim_boundary.not_supported must be a list")
    if not isinstance(does_not_prove, list):
        fail("does_not_prove must be a list")

    for field_name, values in (
        ("claim_boundary.not_supported", not_supported),
        ("does_not_prove", does_not_prove),
    ):
        missing = sorted(REQUIRED_UNSUPPORTED_CLAIMS - set(values))
        if missing:
            fail(f"{field_name} missing entries: {', '.join(missing)}")


def iter_strings(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, list):
        found: list[tuple[tuple[str, ...], str]] = []
        for item in value:
            found.extend(iter_strings(item, path))
        return found
    if isinstance(value, dict):
        found = []
        for key, item in value.items():
            found.extend(iter_strings(item, path + (str(key),)))
        return found
    return []


def reject_promotional_claims(sample: dict[str, Any]) -> None:
    for path, text in iter_strings(sample):
        negative_context = path in ALLOWED_NEGATIVE_PATHS
        for pattern in PROMOTIONAL_PATTERNS:
            if re.search(pattern, text, flags=re.IGNORECASE) and not negative_context:
                fail(f"promotional claim outside negative boundary at {'.'.join(path)}: {text!r}")


def reject_executed_actions(sample: dict[str, Any]) -> None:
    for path, text in iter_strings(sample):
        if path in ALLOWED_NEGATIVE_PATHS:
            continue
        for pattern in EXECUTED_ACTION_PATTERNS:
            if re.search(pattern, text, flags=re.IGNORECASE):
                fail(f"executed action wording found at {'.'.join(path)}: {text!r}")


def reject_unsupported_disposition_language(sample: dict[str, Any]) -> None:
    for path, text in iter_strings(sample):
        if path in {("blocked_actions",), *ALLOWED_NEGATIVE_PATHS}:
            continue
        for pattern in UNSUPPORTED_DISPOSITION_PATTERNS:
            if re.search(pattern, text, flags=re.IGNORECASE):
                fail(f"unsupported disposition wording found at {'.'.join(path)}: {text!r}")


def reject_private_or_secret_leakage(sample: dict[str, Any]) -> None:
    text = json.dumps(sample, sort_keys=True)
    allowed_schema_terms = {
        "raw_event_included",
        "raw_value_included",
        "raw_command_line_included",
        "source_event_refs",
    }
    scan_text = text
    for term in allowed_schema_terms:
        scan_text = scan_text.replace(term, "")

    for pattern in PRIVATE_LEAK_PATTERNS:
        if re.search(pattern, scan_text):
            fail(f"secret or raw private pattern found: {pattern}")
    for pattern in PRIVATE_OR_RECRUITER_TERMS:
        if re.search(pattern, scan_text):
            fail(f"private/recruiter/internal term found: {pattern}")


def require_metric_consistency(sample: dict[str, Any]) -> None:
    metrics = sample.get("automation_metrics")
    if not isinstance(metrics, dict):
        fail("automation_metrics must be an object")
    checklist = sample.get("analyst_checklist")
    blocked = sample.get("blocked_actions")
    event_refs = sample.get("source_event_refs")
    gates = sample.get("response_gates")
    if not isinstance(checklist, list) or metrics.get("checklist_steps") != len(checklist):
        fail("automation_metrics.checklist_steps must equal analyst_checklist length")
    if not isinstance(blocked, list) or metrics.get("blocked_action_count") != len(blocked):
        fail("automation_metrics.blocked_action_count must equal blocked_actions length")
    if not isinstance(event_refs, list) or metrics.get("sanitized_event_ref_count") != len(event_refs):
        fail("automation_metrics.sanitized_event_ref_count must equal source_event_refs length")
    if not isinstance(gates, dict) or metrics.get("human_gate_count") != len(gates):
        fail("automation_metrics.human_gate_count must equal response_gates count")
    if metrics.get("deterministic_validation") is not True:
        fail("automation_metrics.deterministic_validation must be true")


def main() -> int:
    sample = load_json(SAMPLE_PATH)
    schema = load_json(SCHEMA_PATH)

    validate_schema_if_possible(sample, schema)
    require_expected_values(sample)
    require_blocked_actions(sample)
    require_unsupported_claim_inventory(sample)
    require_metric_consistency(sample)
    reject_promotional_claims(sample)
    reject_executed_actions(sample)
    reject_unsupported_disposition_language(sample)
    reject_private_or_secret_leakage(sample)

    print("SOAR_CASE_PACKET_V0=pass")
    print("CLAIM_CEILING=SOAR_STYLE_ANALYST_SUPPORT_CONTRACT_WITH_DETERMINISTIC_VALIDATION")
    print("HUMAN_REVIEW_REQUIRED=true")
    print("AI_DECIDED_DISPOSITION=false")
    print("PUBLIC_SAFE=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
