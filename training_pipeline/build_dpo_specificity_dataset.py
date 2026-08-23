import argparse
import json
import random
import re
from pathlib import Path


INSTRUCTION = (
    "You are MitigLLM, a Purple Team cybersecurity assistant. "
    "Given a vulnerability description, write practical mitigation guidance for a security analyst. "
    "Use concrete actions: patching, configuration, compensating controls, detection, and validation. "
    "Do not invent CVE IDs, product names, or fixed versions."
)


CATEGORY_SPECIFIC_CONTROLS = {
    "sql_injection": [
        "Replace the vulnerable fuzzy-search SQL construction with parameterized queries or prepared statements for every user-controlled field.",
        "Escape wildcard characters used in LIKE queries and validate search fields with strict allowlists.",
        "Add regression tests for authentication bypass, stacked queries, boolean-based SQLi, and time-delay payloads against the affected search endpoint.",
        "Monitor database errors, unusual query patterns, and access to sensitive tables from the application account.",
    ],
    "xss": [
        "Apply context-aware output encoding for HTML body, attribute, URL, JavaScript, and CSS contexts.",
        "Sanitize user-controlled HTML with a maintained sanitizer and block event handlers, script tags, and dangerous URL schemes.",
        "Deploy a restrictive Content Security Policy that removes inline script execution where possible.",
        "Add reflected, stored, and DOM XSS regression tests around the affected parameter or page.",
    ],
    "rce": [
        "Disable or restrict the vulnerable execution path until the patched version is deployed.",
        "Block unauthenticated access to the affected endpoint or management interface with network and identity controls.",
        "Run the service under a low-privilege account and isolate it from secrets, internal networks, and writeable system paths.",
        "Monitor child process creation, dropped files, outbound callbacks, and abnormal interpreter execution.",
    ],
    "command_injection": [
        "Remove shell invocation and call safe language APIs with fixed executable paths and explicit argument arrays.",
        "Validate command parameters with allowlists and reject shell metacharacters, pipes, redirects, and command separators.",
        "Run the component under least privilege with restricted filesystem and network permissions.",
        "Alert on unexpected shell interpreters, child processes, and outbound connections from the affected service.",
    ],
    "path_traversal": [
        "Canonicalize paths before authorization and reject traversal sequences after URL decoding and normalization.",
        "Restrict reads and writes to an application-owned base directory and deny symlink escapes.",
        "Avoid passing raw user-controlled paths into filesystem APIs.",
        "Add tests for encoded traversal, alternate separators, null bytes, and symlink cases.",
    ],
    "ssrf": [
        "Use a strict destination allowlist for server-side fetches and block private, loopback, link-local, and metadata IP ranges.",
        "Enforce egress filtering so the application cannot reach cloud metadata services or internal-only hosts.",
        "Disable redirects or revalidate each redirect target before following it.",
        "Log requested destinations and alert on internal IP ranges, unusual schemes, or metadata-service access attempts.",
    ],
    "authz": [
        "Enforce server-side authorization checks for every object and action, including tenant ownership checks.",
        "Review roles, permissions, and object-level access decisions on the affected endpoint.",
        "Add regression tests for cross-tenant access, unauthenticated requests, and privilege-boundary violations.",
        "Review access logs for unauthorized operations during the exposure window.",
    ],
    "privilege_escalation": [
        "Patch the affected utility or shell component and remove unnecessary privileged execution paths.",
        "Review service accounts, sudo rules, local permissions, writable directories, and scheduled tasks.",
        "Harden administrative interfaces and ensure the vulnerable path cannot run with root privileges.",
        "Monitor new admin accounts, privilege changes, suspicious local execution, and modified privileged binaries.",
    ],
    "memory_safety": [
        "Upgrade to a fixed build compiled with modern memory-safety protections.",
        "Disable or restrict the vulnerable parser, protocol, or file type until the fix is deployed.",
        "Add fuzzing and regression tests around the affected input parsing path.",
        "Monitor crashes, abnormal control flow, exploit attempts, and repeated malformed inputs.",
    ],
    "csrf": [
        "Require anti-CSRF tokens for every state-changing request.",
        "Validate SameSite cookie settings and check Origin or Referer headers for sensitive actions.",
        "Avoid state changes over GET and require re-authentication for high-risk operations.",
        "Add regression tests for forged forms, cross-origin requests, and missing-token cases.",
    ],
    "information_disclosure": [
        "Remove the exposed data path and patch the affected component.",
        "Rotate credentials, API keys, session secrets, or certificates if sensitive data may have been exposed.",
        "Reduce error verbosity and prevent sensitive values from being returned in responses or logs.",
        "Review access logs to identify which users, tokens, or systems accessed the exposed information.",
    ],
    "dos": [
        "Add request size, rate, timeout, and concurrency limits around the vulnerable operation.",
        "Configure CPU, memory, queue, and expensive-operation quotas for the affected service.",
        "Deploy circuit breakers or backpressure for the path that can be abused for resource exhaustion.",
        "Monitor CPU, memory, error rate, queue depth, and request spikes tied to the affected endpoint.",
    ],
    "crypto": [
        "Upgrade the affected cryptographic library or configuration to a supported fixed version.",
        "Disable weak protocols, weak ciphers, insecure certificate validation, and deprecated key sizes.",
        "Rotate keys or certificates if compromise or incorrect validation may have exposed secrets.",
        "Validate the final TLS or crypto policy with automated configuration checks.",
    ],
    "supply_chain": [
        "Pin the dependency to a clean fixed release and verify the package source before deployment.",
        "Validate package provenance, signatures, lockfiles, and build artifacts in CI.",
        "Remove compromised or vulnerable package versions from build caches and deployment images.",
        "Add dependency scanning, SBOM generation, and release gates for future builds.",
    ],
    "open_redirect": [
        "Validate redirect targets against an allowlist of trusted relative paths or domains.",
        "Reject protocol-relative, encoded, nested, and external redirect values unless explicitly trusted.",
        "Avoid reflecting user-controlled URLs directly into redirect responses.",
        "Log rejected redirect attempts and monitor for phishing abuse.",
    ],
}


WEAK_REJECTED_TEMPLATES = [
    (
        "Mitigation plan:\n"
        "- Apply vendor patches where available.\n"
        "- Review configuration and follow security best practices.\n"
        "- Monitor the affected system for suspicious activity.\n"
        "- Validate that the issue is fixed after remediation."
    ),
    (
        "Mitigation plan:\n"
        "- Update the affected software.\n"
        "- Restrict access to the vulnerable system.\n"
        "- Follow secure configuration guidelines.\n"
        "- Check logs for unusual activity."
    ),
    (
        "Mitigation plan:\n"
        "- Investigate the vulnerability and assess risk.\n"
        "- Patch the application when possible.\n"
        "- Use monitoring and access controls.\n"
        "- Confirm the system is secure after changes."
    ),
]


FOCUS_CATEGORIES = {
    "general",
    "crypto",
    "dos",
    "memory_safety",
    "privilege_escalation",
    "sql_injection",
    "csrf",
    "information_disclosure",
    "authz",
    "path_traversal",
    "rce",
}


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def prompt_for(vulnerability: str) -> str:
    return f"{INSTRUCTION}\n\nVulnerability description:\n{vulnerability.strip()}"


def category_parts(category: str | None) -> list[str]:
    if not category:
        return ["general"]
    return [part.strip() for part in category.split("+") if part.strip()]


def primary_category(category: str | None) -> str:
    return category_parts(category)[0]


def extract_versions(text: str) -> list[str]:
    found = re.findall(r"(?:>=|<=|>|<|=)?\s*v?\d+(?:\.\d+){1,3}", text)
    cleaned = []
    for value in found:
        value = re.sub(r"\s+", "", value)
        if value not in cleaned:
            cleaned.append(value)
    return cleaned[:4]


def extract_component_hint(text: str) -> str | None:
    patterns = [
        r"\bin the ([A-Z][A-Za-z0-9_. -]{2,60})",
        r"\bthe ([A-Za-z0-9_.-]+) (?:package|plugin|library|platform|application|component|service)\b",
        r"\b([A-Za-z0-9_.-]+) (?:npm package|package|plugin|library)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            hint = match.group(1).strip(" .,:;")
            if 2 <= len(hint) <= 70:
                return hint
    return None


def extract_feature_hint(text: str) -> str | None:
    candidates = [
        "fuzzy search",
        "login",
        "metadata service",
        "redirect",
        "parser",
        "command-line utility",
        "shell",
        "file upload",
        "authentication",
        "authorization",
        "certificate validation",
    ]
    lowered = text.lower()
    hits = [candidate for candidate in candidates if candidate in lowered]
    return ", ".join(hits[:3]) if hits else None


def infer_extra_parts(vulnerability: str, category: str | None) -> list[str]:
    lowered = vulnerability.lower()
    inferred = set(category_parts(category))
    rules = [
        ("sql_injection", [r"\bsql\b", r"\bsqli\b", r"\bdatabase\b", r"\bquery\b"]),
        ("xss", [r"\bxss\b", r"cross-site scripting", r"\bscript\b"]),
        ("csrf", [r"\bcsrf\b", r"cross-site request forgery"]),
        ("rce", [r"remote code execution", r"arbitrary code execution", r"\brce\b"]),
        ("command_injection", [r"command injection", r"\bshell\b", r"os command"]),
        ("path_traversal", [r"path traversal", r"directory traversal", r"\.\./"]),
        ("ssrf", [r"\bssrf\b", r"metadata service", r"server-side request forgery"]),
        ("authz", [r"authorization", r"access control", r"authentication bypass", r"\bidor\b", r"tenant"]),
        ("privilege_escalation", [r"privilege escalation", r"\broot\b", r"\badmin\b"]),
        ("memory_safety", [r"buffer overflow", r"use-after-free", r"out-of-bounds", r"memory corruption"]),
        ("information_disclosure", [r"information disclosure", r"data leak", r"sensitive information", r"exposure"]),
        ("dos", [r"denial of service", r"resource exhaustion", r"\bdos\b", r"\bcrash\b"]),
        ("crypto", [r"\btls\b", r"certificate", r"cipher", r"cryptographic", r"encryption"]),
        ("supply_chain", [r"dependency", r"package", r"npm", r"pypi", r"supply chain"]),
        ("deserialization", [r"deserialization", r"deserialize", r"object injection"]),
        ("open_redirect", [r"open redirect", r"redirect"]),
    ]
    for name, patterns in rules:
        if any(re.search(pattern, lowered) for pattern in patterns):
            inferred.add(name)
    return [part for part in inferred if part != "general"]


def context_lines(vulnerability: str) -> list[str]:
    lines = []
    component = extract_component_hint(vulnerability)
    feature = extract_feature_hint(vulnerability)
    versions = extract_versions(vulnerability)
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", vulnerability, flags=re.I)))
    if component:
        lines.append(f"- Treat `{component}` as the affected component named in the advisory and verify the exact deployment/version in your environment.")
    if feature:
        lines.append(f"- Focus remediation on the exposed feature/path mentioned in the prompt: {feature}.")
    if versions:
        lines.append(f"- Preserve the version evidence from the prompt and prioritize upgrade guidance around: {', '.join(versions)}.")
    if cves:
        lines.append(f"- Track the referenced CVE(s) without adding new identifiers: {', '.join(cves)}.")
    if not lines:
        lines.append("- The prompt does not name a precise component or CVE, so avoid inventing one and document the missing evidence during triage.")
    return lines


def build_specific_chosen(item: dict) -> str:
    vulnerability = item.get("input", "")
    category = item.get("category") or "general"
    parts = infer_extra_parts(vulnerability, category)
    judge = item.get("judge", {})
    advice = judge.get("correction_advice", "")

    controls = []
    for part in parts:
        controls.extend(CATEGORY_SPECIFIC_CONTROLS.get(part, []))
    if not controls:
        controls = [
            "Identify the affected component, exposed entry point, user-controlled input, and trust boundary before remediation.",
            "Patch or disable the vulnerable feature and document the compensating controls used before the permanent fix.",
            "Add targeted regression tests that reproduce the vulnerable behavior and prove it is no longer exploitable.",
            "Monitor logs and telemetry for indicators tied to the affected component and exposure path.",
        ]
    controls = list(dict.fromkeys(controls))[:8]

    lines = [
        "Mitigation plan:",
        f"- Triage this as `{category}` and map the vulnerable input, affected component, exposure path, and business impact before changing production.",
    ]
    lines.extend(context_lines(vulnerability))
    lines.append("- Apply the vendor patch or upgrade to the fixed release mentioned in the prompt when available; otherwise disable or isolate the affected feature until remediation is complete.")
    lines.extend(f"- {control}" for control in controls)
    lines.extend(
        [
            "- Add compensating controls around the affected path: network restrictions, least privilege, input validation, and focused monitoring.",
            "- Validate the fix with a proof-of-fix test that exercises the exact vulnerable path described in the prompt.",
            "- Review historical logs for exploitation attempts and document residual risk, owner, rollout date, and rollback plan.",
        ]
    )
    if advice and advice.lower() not in {"none", "n/a"}:
        lines.append(f"- Specificity note for the analyst: {advice.rstrip('.')}.")
    return "\n".join(lines)


def weak_rejected_for(item: dict, index: int) -> str:
    return WEAK_REJECTED_TEMPLATES[index % len(WEAK_REJECTED_TEMPLATES)]


def build_from_curated_rows(rows: list[dict], limit: int, per_category_cap: int) -> list[dict]:
    buckets: dict[str, list[dict]] = {}
    for row in rows:
        category = row.get("category") or "general"
        key = primary_category(category)
        buckets.setdefault(key, []).append(row)

    selected = []
    focus_keys = [key for key in sorted(buckets) if key in FOCUS_CATEGORIES]
    other_keys = [key for key in sorted(buckets) if key not in FOCUS_CATEGORIES]
    for key in focus_keys + other_keys:
        random.shuffle(buckets[key])
        cap = per_category_cap if key in FOCUS_CATEGORIES else max(10, per_category_cap // 3)
        selected.extend(buckets[key][:cap])
        if len(selected) >= limit:
            break

    if len(selected) < limit:
        remaining = [row for bucket in buckets.values() for row in bucket if row not in selected]
        random.shuffle(remaining)
        selected.extend(remaining[: limit - len(selected)])

    selected = selected[:limit]
    preferences = []
    for idx, row in enumerate(selected):
        item = {
            "input": row.get("input", ""),
            "category": row.get("category"),
            "judge": {},
        }
        preferences.append(
            {
                "prompt": prompt_for(row.get("input", "")),
                "chosen": build_specific_chosen(item),
                "rejected": weak_rejected_for(item, idx),
                "category": row.get("category"),
                "source_index": idx,
                "preference_source": "curated_v2_specific_vs_generic",
                "judge_verdict": None,
                "judge_average_score": None,
                "judge_specificity": None,
                "rule_audit_verdict": None,
            }
        )
    return preferences


def load_judge_by_index(path: Path | None) -> dict[int, dict]:
    if not path:
        return {}
    return {int(row["index"]): row for row in read_jsonl(path)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build DPO preference data focused on cybersecurity specificity.")
    parser.add_argument("--judge-file", default="reports/llm_judge_outputs_50_mistral_nemo.jsonl")
    parser.add_argument("--curated-file", default=None)
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--per-category-cap", type=int, default=90)
    parser.add_argument("--rule-audit-file", default=None)
    parser.add_argument("--output", default="data/preferences/dpo_specificity.jsonl")
    parser.add_argument("--train-output", default="data/preferences/dpo_specificity_train.jsonl")
    parser.add_argument("--val-output", default="data/preferences/dpo_specificity_val.jsonl")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    args = parser.parse_args()

    random.seed(args.seed)
    if args.curated_file:
        preferences = build_from_curated_rows(read_jsonl(Path(args.curated_file)), args.limit, args.per_category_cap)
    else:
        rows = read_jsonl(Path(args.judge_file))
        rule_rows = load_judge_by_index(Path(args.rule_audit_file)) if args.rule_audit_file else {}

        preferences = []
        for row in rows:
            judge = row.get("judge", {})
            verdict = judge.get("verdict")
            generated = row.get("generated", "").strip()
            if verdict == "pass" and judge.get("use_for_dpo"):
                chosen = generated
                rejected = weak_rejected_for(row, len(preferences))
                source = "judge_pass_vs_generic"
            else:
                chosen = build_specific_chosen(row)
                rejected = generated if generated else weak_rejected_for(row, len(preferences))
                source = "specific_rewrite_vs_reviewed_output"

            preferences.append(
                {
                    "prompt": prompt_for(row.get("input", "")),
                    "chosen": chosen,
                    "rejected": rejected,
                    "category": row.get("category"),
                    "source_index": row.get("index"),
                    "preference_source": source,
                    "judge_verdict": verdict,
                    "judge_average_score": judge.get("average_score"),
                    "judge_specificity": judge.get("scores", {}).get("specificity"),
                    "rule_audit_verdict": rule_rows.get(int(row.get("index", -1)), {}).get("verdict"),
                }
            )

    random.shuffle(preferences)
    val_size = max(1, int(len(preferences) * args.val_ratio)) if len(preferences) > 5 else 1
    val_rows = preferences[:val_size]
    train_rows = preferences[val_size:]

    write_jsonl(preferences, Path(args.output))
    write_jsonl(train_rows, Path(args.train_output))
    write_jsonl(val_rows, Path(args.val_output))

    summary = {
        "total": len(preferences),
        "train": len(train_rows),
        "validation": len(val_rows),
        "preference_sources": {},
    }
    for row in preferences:
        summary["preference_sources"][row["preference_source"]] = summary["preference_sources"].get(row["preference_source"], 0) + 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
