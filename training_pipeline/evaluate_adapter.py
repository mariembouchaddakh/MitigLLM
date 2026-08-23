import argparse
import json
import re
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig


INSTRUCTION = (
    "You are MitigLLM, a Purple Team cybersecurity assistant. "
    "Given a vulnerability description, write practical mitigation guidance for a security analyst. "
    "Use concrete actions: patching, configuration, compensating controls, detection, and validation. "
    "Do not invent CVE IDs, product names, or fixed versions."
)


def load_jsonl(path: Path, limit: int | None) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if limit and len(rows) >= limit:
                break
            rows.append(json.loads(line))
    return rows


def build_prompt(vulnerability: str) -> str:
    return (
        f"<s>[INST] {INSTRUCTION}\n\n"
        f"Vulnerability description:\n{vulnerability.strip()} [/INST]"
    )


def extract_cves(text: str) -> set[str]:
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE))


def score_output(prompt: str, output: str) -> dict:
    output_lower = output.lower()
    expected_terms = {
        "patch_or_upgrade": ["patch", "upgrade", "fixed release", "vendor fix"],
        "configuration": ["configure", "configuration", "disable", "restrict", "isolate"],
        "compensating_controls": ["compensating", "least privilege", "network", "segmentation", "access"],
        "detection": ["monitor", "log", "telemetry", "alert", "indicator"],
        "validation": ["test", "validate", "regression", "proof-of-fix"],
    }
    coverage = {
        key: any(term in output_lower for term in terms)
        for key, terms in expected_terms.items()
    }
    prompt_cves = extract_cves(prompt)
    output_cves = extract_cves(output)
    invented_cves = sorted(output_cves - prompt_cves)
    return {
        "chars": len(output),
        "has_mitigation_plan": "mitigation plan" in output_lower,
        "coverage": coverage,
        "coverage_count": sum(coverage.values()),
        "invented_cves": invented_cves,
        "passes_basic_checks": (
            len(output) >= 350
            and "mitigation plan" in output_lower
            and sum(coverage.values()) >= 4
            and not invented_cves
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate MitigLLM LoRA adapter on test prompts.")
    parser.add_argument("--base-model", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--test-file", default="data/curated/test.jsonl")
    parser.add_argument("--output", default="reports/eval_adapter_outputs.jsonl")
    parser.add_argument("--summary", default="reports/eval_adapter_summary.json")
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--max-new-tokens", type=int, default=260)
    parser.add_argument("--temperature", type=float, default=0.25)
    args = parser.parse_args()

    rows = load_jsonl(Path(args.test_file), args.limit)
    output_path = Path(args.output)
    summary_path = Path(args.summary)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(args.adapter, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb_config,
        device_map="auto",
        dtype=torch.bfloat16,
        trust_remote_code=True,
    )
    model = PeftModel.from_pretrained(base, args.adapter)
    model.eval()

    results = []
    with output_path.open("w", encoding="utf-8") as handle:
        for idx, row in enumerate(rows):
            prompt = build_prompt(row["input"])
            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
            with torch.no_grad():
                generated = model.generate(
                    **inputs,
                    max_new_tokens=args.max_new_tokens,
                    temperature=args.temperature,
                    top_p=0.9,
                    do_sample=args.temperature > 0,
                    pad_token_id=tokenizer.eos_token_id,
                )
            new_tokens = generated[0][inputs["input_ids"].shape[-1]:]
            output = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
            score = score_output(row["input"], output)
            result = {
                "index": idx,
                "category": row.get("category"),
                "input": row["input"],
                "reference": row.get("output"),
                "generated": output,
                "score": score,
            }
            results.append(result)
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")
            print(f"{idx + 1}/{len(rows)} pass={score['passes_basic_checks']} coverage={score['coverage_count']} chars={score['chars']}")

    pass_count = sum(item["score"]["passes_basic_checks"] for item in results)
    invented = sum(bool(item["score"]["invented_cves"]) for item in results)
    summary = {
        "evaluated": len(results),
        "basic_pass_rate": pass_count / max(1, len(results)),
        "basic_pass_count": pass_count,
        "invented_cve_count": invented,
        "average_chars": sum(item["score"]["chars"] for item in results) / max(1, len(results)),
        "outputs_file": str(output_path),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
