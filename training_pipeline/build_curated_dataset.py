import argparse
import json
import random
import re
from pathlib import Path


VULNERABILITY_MARKER = "### Vulnerability:"
MITIGATION_MARKER = "### Mitigation:"


CATEGORY_RULES = [
    ("sql_injection", r"\bsql injection\b|\bsqli\b|\bdatabase query\b", [
        "Replace dynamic SQL string concatenation with parameterized queries or prepared statements.",
        "Validate and normalize every user-controlled field with strict allowlists.",
        "Reduce database privileges for the application account and separate read/write roles where possible.",
        "Add tests that attempt authentication bypass, stacked queries, boolean-based injection, and time-based payloads.",
    ]),
    ("xss", r"\bcross[- ]site scripting\b|\bxss\b|\bscript injection\b", [
        "Apply context-aware output encoding for HTML, JavaScript, URL, CSS, and attribute contexts.",
        "Sanitize user-controlled HTML with a maintained sanitizer and block dangerous tags and event handlers.",
        "Deploy a restrictive Content Security Policy and remove inline script execution where possible.",
        "Add regression tests for reflected, stored, and DOM-based payloads.",
    ]),
    ("rce", r"\bremote code execution\b|\brce\b|arbitrary code execution|\bcode execution\b", [
        "Upgrade the affected component immediately or disable the vulnerable feature until a fix is deployed.",
        "Restrict access to the vulnerable endpoint or management interface with network controls and authentication.",
        "Run the service with least privilege and isolate it from sensitive internal systems.",
        "Monitor process creation, outbound callbacks, dropped files, and abnormal child processes.",
    ]),
    ("command_injection", r"\bcommand injection\b|\bos command\b|\bshell command\b", [
        "Avoid shell invocation and use safe language APIs with explicit argument arrays.",
        "Validate command parameters with strict allowlists and reject shell metacharacters.",
        "Run the affected service under a low-privilege account and restrict filesystem access.",
        "Alert on unusual process execution, command interpreters, and unexpected outbound connections.",
    ]),
    ("path_traversal", r"\bpath traversal\b|\bdirectory traversal\b|\b\.\./\b|\bfile path\b", [
        "Canonicalize requested paths before authorization and block traversal sequences.",
        "Restrict file reads and writes to an application-controlled base directory.",
        "Avoid exposing raw user-controlled paths to filesystem APIs.",
        "Add tests for encoded traversal payloads, symbolic links, and alternate path separators.",
    ]),
    ("ssrf", r"\bssrf\b|server-side request forgery|\bmetadata service\b", [
        "Use destination allowlists for server-side requests and block private, loopback, link-local, and metadata IP ranges.",
        "Enforce egress filtering at the network layer and deny direct access to cloud metadata services.",
        "Disable redirects or revalidate every redirect target before following it.",
        "Log requested destinations and alert on internal address ranges or unusual protocols.",
    ]),
    ("authz", r"\bauthorization\b|\baccess control\b|\bauthentication bypass\b|\bauth bypass\b|\bidor\b|\btenant\b", [
        "Enforce server-side authorization checks for every object and action, including tenant ownership checks.",
        "Review roles, permissions, and object-level access decisions around the affected endpoint.",
        "Add regression tests for cross-tenant access, privilege boundaries, and unauthenticated requests.",
        "Review access logs for unauthorized operations during the exposure window.",
    ]),
    ("privilege_escalation", r"\bprivilege escalation\b|\belevation of privilege\b|\badmin privileges\b|\broot\b", [
        "Apply the vendor patch and remove unnecessary privileged execution paths.",
        "Review service accounts, local permissions, writable directories, and scheduled tasks.",
        "Use least privilege and harden administrative interfaces.",
        "Monitor for unexpected privilege changes, new admin accounts, and suspicious local execution.",
    ]),
    ("deserialization", r"\bdeserialization\b|deserialize|pickle|yaml load|object injection", [
        "Do not deserialize untrusted data with unsafe serializers.",
        "Use strict schemas, signatures, or allowlisted types before parsing serialized input.",
        "Isolate the parser and disable gadget chains or dynamic class loading where possible.",
        "Monitor for unexpected object creation, command execution, and suspicious payload markers.",
    ]),
    ("memory_safety", r"\bbuffer overflow\b|\bmemory corruption\b|\buse-after-free\b|\bout-of-bounds\b|\bheap\b|\bstack overflow\b", [
        "Upgrade to a fixed build compiled with modern memory safety protections.",
        "Disable or restrict the vulnerable parser, protocol, or file type until remediation is complete.",
        "Add fuzzing and regression tests around the affected input handling path.",
        "Monitor crashes, exploit attempts, and abnormal control-flow behavior.",
    ]),
    ("csrf", r"\bcsrf\b|cross-site request forgery", [
        "Require anti-CSRF tokens for all state-changing requests.",
        "Validate SameSite cookie settings and origin or referer headers.",
        "Avoid state changes over GET requests and re-authenticate sensitive actions.",
        "Add regression tests for forged form submissions and cross-origin requests.",
    ]),
    ("information_disclosure", r"\binformation disclosure\b|\binfo disclosure\b|\bdata leak\b|\bexposure\b|\bsensitive information\b", [
        "Patch the affected component and remove the exposed data path.",
        "Rotate credentials, API keys, or session secrets if sensitive data may have been exposed.",
        "Reduce error verbosity and prevent sensitive values from being returned in responses or logs.",
        "Review access logs to identify which users or systems accessed the exposed information.",
    ]),
    ("dos", r"\bdenial of service\b|\bdos\b|\bresource exhaustion\b|\bcrash\b|\buncontrolled resource\b", [
        "Upgrade the affected service and add input size, request rate, and timeout limits.",
        "Configure resource quotas for CPU, memory, request bodies, and expensive operations.",
        "Deploy circuit breakers or queue limits around the vulnerable path.",
        "Monitor CPU, memory, error rates, queue depth, and request spikes.",
    ]),
    ("open_redirect", r"\bopen redirect\b|\bredirect\b", [
        "Validate redirect targets against an allowlist of trusted relative paths or domains.",
        "Avoid reflecting user-controlled URLs directly into redirect responses.",
        "Add tests for encoded, nested, and protocol-relative redirect payloads.",
        "Log rejected redirect attempts and monitor for phishing abuse.",
    ]),
    ("crypto", r"\bcrypto\b|\bcryptographic\b|\bencryption\b|\btls\b|\bcertificate\b|\bweak cipher\b", [
        "Upgrade the affected cryptographic library or configuration to a supported version.",
        "Disable weak protocols, weak ciphers, and insecure certificate validation behavior.",
        "Rotate affected keys or certificates if compromise is possible.",
        "Validate the final configuration with automated TLS and crypto policy checks.",
    ]),
    ("supply_chain", r"\bsupply chain\b|\bdependency\b|\bpackage\b|\bmalicious package\b|\btyposquatting\b", [
        "Pin trusted dependency versions and upgrade to a clean, verified release.",
        "Verify package provenance, signatures, lockfiles, and build artifacts.",
        "Remove compromised packages from the environment and rotate exposed credentials.",
        "Add dependency scanning, SBOM generation, and CI checks for future releases.",
    ]),
]


GENERIC_CONTROLS = [
    "Upgrade or patch the affected component to a fixed version as soon as possible.",
    "Reduce exposure of the vulnerable service with network segmentation, authentication, and least privilege.",
    "Add regression tests that reproduce the vulnerable behavior and confirm the mitigation.",
    "Review logs and telemetry for exploitation attempts during the exposure window.",
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
    if len(vulnerability) < 45:
        return None
    return {"input": vulnerability, "source_output": mitigation}


def classify(vulnerability: str) -> tuple[str, list[str]]:
    lowered = vulnerability.lower()
    matches = []
    controls = []
    for category, pattern, category_controls in CATEGORY_RULES:
        if re.search(pattern, lowered):
            matches.append(category)
            controls.extend(category_controls)
    if not matches:
        return "general", GENERIC_CONTROLS
    deduped = list(dict.fromkeys(controls))
    return "+".join(matches[:3]), deduped[:7]


def extract_cves(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))


def extract_versions(text: str) -> list[str]:
    patterns = [
        r"\b(?:before|prior to|through|up to|versions?)\s+v?\d+(?:\.\d+){0,3}",
        r"\bv?\d+(?:\.\d+){1,3}\b",
    ]
    found = []
    for pattern in patterns:
        found.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    normalized = []
    for value in found:
        value = re.sub(r"^(before|prior to|through|up to|versions?)\s+", "", value, flags=re.IGNORECASE)
        value = value.strip()
        if value and value.lower() not in {item.lower() for item in normalized}:
            normalized.append(value)
    return normalized[:5]


def source_is_good(vulnerability: str, mitigation: str) -> bool:
    if len(mitigation) < 180:
        return False
    if mitigation in vulnerability or vulnerability[:180] in mitigation:
        return False
    action_terms = [
        "upgrade", "patch", "validate", "sanitize", "restrict", "disable",
        "monitor", "review", "configure", "enforce", "rotate", "apply",
    ]
    lower = mitigation.lower()
    return sum(term in lower for term in action_terms) >= 2


def build_output(vulnerability: str, source_output: str) -> tuple[str, str, str]:
    category, controls = classify(vulnerability)
    cves = extract_cves(vulnerability)
    versions = extract_versions(vulnerability)
    good_source = source_is_good(vulnerability, source_output)

    context_bits = []
    if cves:
        context_bits.append(f"Referenced CVE(s): {', '.join(cves)}.")
    if versions:
        context_bits.append(f"Affected version indicators: {', '.join(versions)}.")
    context = " ".join(context_bits) if context_bits else "No explicit CVE or fixed version is provided in the prompt."

    lines = [
        "Mitigation plan:",
        f"- Triage the issue as category `{category}` and confirm the affected component, version, and exposure path.",
        f"- {context}",
        "- Apply the vendor patch or upgrade to a fixed release. If no patch is available, disable or isolate the vulnerable feature until remediation is possible.",
    ]
    for control in controls:
        lines.append(f"- {control}")
    lines.extend([
        "- Add compensating controls such as network restrictions, least privilege, input validation, and monitoring around the affected path.",
        "- Validate the fix with a regression test or proof-of-fix case that demonstrates the vulnerable behavior is no longer exploitable.",
        "- Review historical logs for exploitation indicators and document the remediation decision for the security team.",
    ])
    if good_source:
        lines.append(f"- Source advisory note: {source_output.rstrip('.')}.")
        quality = "source_plus_structured"
    else:
        quality = "curated_structured"

    return "\n".join(list(dict.fromkeys(lines))), category, quality


def instruction() -> str:
    return (
        "You are MitigLLM, a Purple Team cybersecurity assistant. "
        "Given a vulnerability description, write practical mitigation guidance for a security analyst. "
        "Use concrete actions: patching, configuration, compensating controls, detection, and validation. "
        "Do not invent CVE IDs, product names, or fixed versions."
    )


def to_text(row: dict) -> str:
    prompt = f"{instruction()}\n\nVulnerability description:\n{row['input']}"
    return f"<s>[INST] {prompt} [/INST] {row['output']}</s>"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a curated high-signal MitigLLM dataset.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", default="data/curated")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-per-category", type=int, default=700)
    parser.add_argument("--val-ratio", type=float, default=0.08)
    parser.add_argument("--test-ratio", type=float, default=0.05)
    args = parser.parse_args()

    source = json.load(open(args.input, encoding="utf-8"))
    rows = []
    rejected: dict[str, int] = {}
    seen = set()

    for record in source:
        parsed = parse_record(record)
        if parsed is None:
            rejected["bad_format_or_short_input"] = rejected.get("bad_format_or_short_input", 0) + 1
            continue
        key = normalize_text(parsed["input"]).lower()
        if key in seen:
            rejected["duplicate_vulnerability"] = rejected.get("duplicate_vulnerability", 0) + 1
            continue
        seen.add(key)
        output, category, quality = build_output(parsed["input"], parsed["source_output"])
        row = {
            "instruction": instruction(),
            "input": parsed["input"],
            "output": output,
            "category": category,
            "quality": quality,
        }
        row["text"] = to_text(row)
        rows.append(row)

    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["category"], []).append(row)

    rng = random.Random(args.seed)
    balanced = []
    for category_rows in grouped.values():
        rng.shuffle(category_rows)
        balanced.extend(category_rows[:args.max_per_category])
    rng.shuffle(balanced)

    test_size = max(1, int(len(balanced) * args.test_ratio))
    val_size = max(1, int(len(balanced) * args.val_ratio))
    test_rows = balanced[:test_size]
    val_rows = balanced[test_size:test_size + val_size]
    train_rows = balanced[test_size + val_size:]

    output_dir = Path(args.output_dir)
    write_jsonl(output_dir / "train.jsonl", train_rows)
    write_jsonl(output_dir / "val.jsonl", val_rows)
    write_jsonl(output_dir / "test.jsonl", test_rows)
    write_jsonl(output_dir / "eval_prompts.jsonl", [
        {
            "input": row["input"],
            "reference": row["output"],
            "category": row["category"],
            "quality": row["quality"],
        }
        for row in test_rows[:150]
    ])

    category_counts: dict[str, int] = {}
    quality_counts: dict[str, int] = {}
    for row in balanced:
        category_counts[row["category"]] = category_counts.get(row["category"], 0) + 1
        quality_counts[row["quality"]] = quality_counts.get(row["quality"], 0) + 1

    report = {
        "source_rows": len(source),
        "curated_rows": len(balanced),
        "train_rows": len(train_rows),
        "val_rows": len(val_rows),
        "test_rows": len(test_rows),
        "quality_counts": quality_counts,
        "category_counts": dict(sorted(category_counts.items(), key=lambda x: (-x[1], x[0]))),
        "rejected": rejected,
        "format": "jsonl: instruction/input/output/category/quality/text",
        "why_better": [
            "Every output follows a consistent mitigation plan.",
            "Weak original answers are replaced by category-specific Purple Team controls.",
            "The model is discouraged from inventing CVEs, products, or fixed versions.",
            "Rows include category and quality metadata for later filtering.",
        ],
    }
    (output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
