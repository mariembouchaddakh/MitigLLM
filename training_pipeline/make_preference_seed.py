import argparse
import json
from pathlib import Path


def weak_answer(vulnerability: str) -> str:
    return (
        "Apply vendor patches where available and monitor the affected system. "
        "Review configuration and follow standard security best practices."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a seed preference dataset from cleaned SFT examples."
    )
    parser.add_argument("--sft-file", default="data/processed/sft_train.jsonl")
    parser.add_argument("--output", default="data/processed/preference_seed.jsonl")
    parser.add_argument("--limit", type=int, default=500)
    args = parser.parse_args()

    rows = []
    with Path(args.sft_file).open(encoding="utf-8") as handle:
        for line in handle:
            if len(rows) >= args.limit:
                break
            item = json.loads(line)
            prompt = (
                f"{item['instruction']}\n\n"
                f"Vulnerability description:\n{item['input']}"
            )
            rows.append(
                {
                    "prompt": prompt,
                    "chosen": item["output"],
                    "rejected": weak_answer(item["input"]),
                }
            )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Wrote {len(rows)} preference seed rows to {output_path}")


if __name__ == "__main__":
    main()
