import argparse
import json
from pathlib import Path


INSTRUCTION = (
    "You are MitigLLM, a Purple Team cybersecurity assistant. "
    "Given a vulnerability description, write practical mitigation guidance for a security analyst. "
    "Use concrete actions: patching, configuration, compensating controls, detection, and validation. "
    "Do not invent CVE IDs, product names, or fixed versions."
)


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def extract_input(prompt: str) -> str:
    marker = "Vulnerability description:"
    if marker in prompt:
        return prompt.split(marker, 1)[1].strip()
    return prompt.strip()


def to_sft_row(row: dict) -> dict:
    vulnerability = extract_input(row["prompt"])
    output = row["chosen"].strip()
    text = (
        f"<s>[INST] {INSTRUCTION}\n\n"
        f"Vulnerability description:\n{vulnerability} [/INST] "
        f"{output}</s>"
    )
    return {
        "instruction": INSTRUCTION,
        "input": vulnerability,
        "output": output,
        "category": row.get("category"),
        "quality": "specificity_preference_chosen",
        "text": text,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert DPO chosen responses into an SFT dataset.")
    parser.add_argument("--train-preferences", default="data/preferences/dpo_specificity_v2_train.jsonl")
    parser.add_argument("--val-preferences", default="data/preferences/dpo_specificity_v2_val.jsonl")
    parser.add_argument("--train-output", default="data/sft_specificity_v2/train.jsonl")
    parser.add_argument("--val-output", default="data/sft_specificity_v2/val.jsonl")
    args = parser.parse_args()

    train_rows = [to_sft_row(row) for row in read_jsonl(Path(args.train_preferences))]
    val_rows = [to_sft_row(row) for row in read_jsonl(Path(args.val_preferences))]
    write_jsonl(train_rows, Path(args.train_output))
    write_jsonl(val_rows, Path(args.val_output))

    summary = {
        "train_rows": len(train_rows),
        "val_rows": len(val_rows),
        "train_output": args.train_output,
        "val_output": args.val_output,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
