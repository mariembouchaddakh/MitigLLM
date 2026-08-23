import argparse
import json
import random
import re
from pathlib import Path


VULNERABILITY_MARKER = "### Vulnerability:"
MITIGATION_MARKER = "### Mitigation:"

CONTROL_PATTERNS = [
    (r"\bsql injection\b|\bsqli\b", [
        "replace string-built SQL queries with parameterized queries or prepared statements",
        "validate and normalize inputs using allowlists for expected fields",
        "review database permissions so the application account has the minimum required privileges",
    ]),
    (r"\bcross[- ]site scripting\b|\bxss\b", [
        "apply context-aware output encoding for HTML, JavaScript, URL, and attribute contexts",
        "sanitize user-controlled HTML with a maintained sanitizer",
        "enable a restrictive Content Security Policy and test common reflected and stored XSS paths",
    ]),
    (r"\bcommand injection\b|\bos command\b", [
        "avoid shell invocation and use safe system APIs with argument arrays",
        "validate command parameters with strict allowlists",
        "run the affected service with least privilege and monitor unusual process creation",
    ]),
    (r"\bpath traversal\b|\bdirectory traversal\b", [
        "canonicalize paths before access checks and block traversal sequences",
        "restrict file access to an application-controlled base directory",
        "avoid exposing user-controlled file paths directly to filesystem APIs",
    ]),
    (r"\bssrf\b|server-side request forgery", [
        "block requests to internal address ranges and metadata services",
        "use destination allowlists for outbound server-side requests",
        "enforce network egress controls and log denied destinations",
    ]),
    (r"\bdeserialization\b|deserialize|pickle|yaml load", [
        "avoid deserializing untrusted data with unsafe serializers",
        "use signed data or strict schema validation before parsing",
        "isolate the parser and monitor unexpected object creation or code execution indicators",
    ]),
    (r"\bauthentication bypass\b|\bauth bypass\b|\bauthorization\b|\baccess control\b", [
        "enforce authorization checks on the server side for every affected action",
        "add regression tests for tenant, role, and object ownership boundaries",
        "review logs for unauthorized access attempts during the vulnerable period",
    ]),
    (r"\bprivilege escalation\b|\belevation of privilege\b", [
        "patch the affected component and remove unnecessary privileged execution paths",
        "review local permissions, service accounts, and writable directories",
        "monitor for suspicious privilege changes and unexpected administrative actions",
    ]),
    (r"\bremote code execution\b|\brce\b|arbitrary code execution", [
        "upgrade or patch the affected component immediately",
        "disable or restrict the vulnerable feature until remediation is complete",
        "add detection for exploit payloads, child process creation, and abnormal network callbacks",
    ]),
    (r"\bbuffer overflow\b|\bmemory corruption\b|\buse-after-free\b|\bout-of-bounds\b", [
        "upgrade to a fixed build compiled with modern memory safety protections",
        "disable the vulnerable parser or input path when possible",
        "add fuzz/regression tests around the affected input handling path",
    ]),
    (r"\bcsrf\b|cross-site request forgery", [
        "require anti-CSRF tokens for state-changing requests",
        "validate SameSite cookie settings and origin or referer headers",
        "avoid using GET requests for state-changing operations",
    ]),
    (r"\binformation disclosure\b|\binfo disclosure\b|\bdata leak\b", [
        "remove the exposed data path and patch the affected component",
        "rotate credentials or secrets if sensitive data may have been exposed",
        "review access logs to identify users or systems that accessed the exposed resource",
    ]),
    (r"\bdenial of service\b|\bdos\b|\bresource exhaustion\b", [
        "upgrade the affected service and add input size or rate limits",
        "configure timeouts and resource quotas for the vulnerable operation",
        "monitor error rates, CPU, memory, and request spikes for exploitation attempts",
    ]),
    (r"\bopen redirect\b", [
        "validate redirect targets against an allowlist of trusted domains",
        "avoid reflecting user-controlled URLs into redirect responses",
        "log rejected redirect attempts for phishing investigation",
    ]),
]


def normalize_text(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def parse_record(record: dict) -> dict | None:
    text = normalize_text(record.get("text", ""))
    if VULNERABILITY_MARKER not in text or MITIGATION_MARKER not in text:
        return None
    before, mitigation = text.split(MITIGATION_MARKER, 1)
    vulnerability = before.split("Description:", 1)[-1]
    vulnerability = normalize_text(vulnerability).lstrip(":").strip()
    mitigation = normalize_text(mitigation)
    if len(vulnerability) < 40 or not mitigation:
        return None
    return {"input": vulnerability, "output": mitigation}


def matched_controls(vulnerability: str) -> list[str]:
    lowered = vulnerability.lower()
    controls = []
    for pattern, pattern_controls in CONTROL_PATTERNS:
        if re.search(pattern, lowered):
            controls.extend(pattern_controls)
    if not controls:
        controls = [
            "upgrade or patch the affected component to a fixed version",
            "reduce exposure of the vulnerable service and enforce least privilege",
            "review logs and telemetry for exploitation attempts",
        ]
    return controls[:5]


def is_weak(example: dict, min_chars: int) -> tuple[bool, str]:
    vulnerability = example["input"]
    mitigation = example["output"]
    lowered = mitigation.lower()
    weak_phrases = [
        "a flaw was found",
        "this issue affects",
        "it does not apply",
        "upgrade to v",
        "unknown",
        "n/a",
    ]
    if len(mitigation) < min_chars:
        return True, "short"
    if mitigation in vulnerability or vulnerability[:160] in mitigation:
        return True, "echo"
    if any(phrase in lowered for phrase in weak_phrases) and len(mitigation) < 220:
        return True, "generic"
    return False, "good"


def repair_mitigation(vulnerability: str, original_mitigation: str) -> str:
    controls = matched_controls(vulnerability)
    lines = [
        "Recommended mitigation:",
        f"- Apply the vendor fix or upgrade the affected component as soon as a patched version is available.",
    ]
    for control in controls:
        lines.append(f"- {control[0].upper()}{control[1:]}.")
    lines.extend([
        "- Add regression tests that reproduce the vulnerable behavior and confirm the mitigation is effective.",
        "- Review application, authentication, and infrastructure logs for signs of exploitation during the exposure window.",
    ])
    if original_mitigation and len(original_mitigation) >= 40 and original_mitigation not in vulnerability:
        lines.append(f"- Preserve this project-specific note from the source advisory: {original_mitigation.rstrip('.')}.")
    return "\n".join(dict.fromkeys(lines))


def build_instruction() -> str:
    return (
        "You are MitigLLM, a Purple Team cybersecurity assistant. "
        "Given a vulnerability description, produce practical mitigation guidance. "
        "Prioritize patching, configuration changes, compensating controls, detection, and validation."
    )


def to_chat_text(example: dict) -> str:
    user = f"{build_instruction()}\n\nVulnerability description:\n{example['input']}"
    return f"<s>[INST] {user.strip()} [/INST] {example['output'].strip()}</s>"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build enhanced MitigLLM SFT dataset.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", default="data/enhanced")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-mitigation-chars", type=int, default=120)
    parser.add_argument("--repair-weak", action="store_true")
    parser.add_argument("--val-ratio", type=float, default=0.08)
    parser.add_argument("--test-ratio", type=float, default=0.05)
    args = parser.parse_args()

    source = json.load(open(args.input, encoding="utf-8"))
    output_dir = Path(args.output_dir)
    rows = []
    rejected: dict[str, int] = {}
    seen_inputs = set()

    for record in source:
        parsed = parse_record(record)
        if parsed is None:
            rejected["bad_format_or_short_input"] = rejected.get("bad_format_or_short_input", 0) + 1
            continue

        input_key = parsed["input"].lower()
        if input_key in seen_inputs:
            rejected["duplicate_vulnerability"] = rejected.get("duplicate_vulnerability", 0) + 1
            continue
        seen_inputs.add(input_key)

        weak, reason = is_weak(parsed, args.min_mitigation_chars)
        quality = "source_good"
        if weak:
            if not args.repair_weak:
                rejected[f"weak_{reason}"] = rejected.get(f"weak_{reason}", 0) + 1
                continue
            parsed["output"] = repair_mitigation(parsed["input"], parsed["output"])
            quality = f"repaired_{reason}"

        item = {
            "instruction": build_instruction(),
            "input": parsed["input"],
            "output": parsed["output"],
            "quality": quality,
        }
        item["text"] = to_chat_text(item)
        rows.append(item)

    random.Random(args.seed).shuffle(rows)
    test_size = max(1, int(len(rows) * args.test_ratio))
    val_size = max(1, int(len(rows) * args.val_ratio))
    test_rows = rows[:test_size]
    val_rows = rows[test_size:test_size + val_size]
    train_rows = rows[test_size + val_size:]

    write_jsonl(output_dir / "train.jsonl", train_rows)
    write_jsonl(output_dir / "val.jsonl", val_rows)
    write_jsonl(output_dir / "test.jsonl", test_rows)
    write_jsonl(output_dir / "eval_prompts.jsonl", [
        {"input": row["input"], "reference": row["output"], "quality": row["quality"]}
        for row in test_rows[:100]
    ])

    quality_counts: dict[str, int] = {}
    for row in rows:
        quality_counts[row["quality"]] = quality_counts.get(row["quality"], 0) + 1

    report = {
        "source_rows": len(source),
        "enhanced_rows": len(rows),
        "train_rows": len(train_rows),
        "val_rows": len(val_rows),
        "test_rows": len(test_rows),
        "quality_counts": quality_counts,
        "rejected": rejected,
        "format": "jsonl: instruction/input/output/quality/text",
        "note": "Rows marked repaired_* are deterministic corrections and should be reviewed before final publication.",
    }
    (output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
