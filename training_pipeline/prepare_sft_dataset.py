import argparse
import json
import random
import re
from pathlib import Path


VULNERABILITY_MARKER = "### Vulnerability:"
MITIGATION_MARKER = "### Mitigation:"


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
    vulnerability = normalize_text(vulnerability)
    mitigation = normalize_text(mitigation)

    if not vulnerability or not mitigation:
        return None

    return {
        "instruction": (
            "You are MitigLLM, a cybersecurity assistant. Given a vulnerability description, "
            "write clear and actionable mitigation guidance for a security analyst."
        ),
        "input": vulnerability,
        "output": mitigation,
    }


def quality_filter(example: dict, min_mitigation_chars: int) -> tuple[bool, str]:
    vulnerability = example["input"]
    mitigation = example["output"]

    if len(mitigation) < min_mitigation_chars:
        return False, "short_mitigation"

    if mitigation in vulnerability:
        return False, "mitigation_copied_from_vulnerability"

    if vulnerability[:160] and vulnerability[:160] in mitigation:
        return False, "vulnerability_echo"

    weak_phrases = [
        "a flaw was found",
        "this issue affects",
        "it does not apply",
        "unknown",
        "n/a",
    ]
    lowered = mitigation.lower()
    if any(phrase in lowered for phrase in weak_phrases) and len(mitigation) < 180:
        return False, "weak_generic_answer"

    return True, "kept"


def to_mistral_sft_text(example: dict) -> str:
    user = f"{example['instruction']}\n\nVulnerability description:\n{example['input']}"
    assistant = example["output"]
    return f"<s>[INST] {user.strip()} [/INST] {assistant.strip()}</s>"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare MitigLLM SFT data.")
    parser.add_argument("--input", required=True, help="Path to the original JSON dataset.")
    parser.add_argument("--output-dir", default="data/processed", help="Output directory.")
    parser.add_argument("--val-ratio", type=float, default=0.08)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-mitigation-chars", type=int, default=80)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    raw_data = json.load(input_path.open(encoding="utf-8"))
    parsed = []
    reject_counts: dict[str, int] = {}
    seen = set()

    for record in raw_data:
        example = parse_record(record)
        if example is None:
            reject_counts["bad_format"] = reject_counts.get("bad_format", 0) + 1
            continue

        key = (example["input"], example["output"])
        if key in seen:
            reject_counts["duplicate"] = reject_counts.get("duplicate", 0) + 1
            continue
        seen.add(key)

        keep, reason = quality_filter(example, args.min_mitigation_chars)
        if not keep:
            reject_counts[reason] = reject_counts.get(reason, 0) + 1
            continue

        parsed.append({**example, "text": to_mistral_sft_text(example)})

    random.Random(args.seed).shuffle(parsed)
    val_size = max(1, int(len(parsed) * args.val_ratio))
    val_rows = parsed[:val_size]
    train_rows = parsed[val_size:]

    write_jsonl(output_dir / "sft_train.jsonl", train_rows)
    write_jsonl(output_dir / "sft_val.jsonl", val_rows)

    report = {
        "source": str(input_path),
        "raw_rows": len(raw_data),
        "kept_rows": len(parsed),
        "train_rows": len(train_rows),
        "val_rows": len(val_rows),
        "rejected": reject_counts,
        "format": "jsonl with instruction/input/output/text fields",
    }
    (output_dir / "dataset_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
