import argparse
from pathlib import Path

import torch
from datasets import load_dataset
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import DPOConfig, DPOTrainer


def main() -> None:
    parser = argparse.ArgumentParser(description="Preference-tune MitigLLM with DPO QLoRA.")
    parser.add_argument("--base-model", required=True, help="Local base model path or HF repo id.")
    parser.add_argument("--sft-adapter", required=True, help="Path to the trained SFT LoRA adapter.")
    parser.add_argument("--train-file", default="data/preferences/dpo_specificity_train.jsonl")
    parser.add_argument("--val-file", default="data/preferences/dpo_specificity_val.jsonl")
    parser.add_argument("--output-dir", default="models/mitigllm-mistral-dpo-specificity")
    parser.add_argument("--max-length", type=int, default=1024)
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--lr", type=float, default=5e-6)
    parser.add_argument("--beta", type=float, default=0.1)
    parser.add_argument("--use-4bit", action="store_true")
    parser.add_argument("--gradient-checkpointing", action="store_true")
    parser.add_argument("--max-train-samples", type=int, default=None)
    parser.add_argument("--max-val-samples", type=int, default=None)
    args = parser.parse_args()

    dataset = load_dataset(
        "json",
        data_files={
            "train": str(Path(args.train_file)),
            "validation": str(Path(args.val_file)),
        },
    )
    if args.max_train_samples:
        dataset["train"] = dataset["train"].select(range(min(args.max_train_samples, len(dataset["train"]))))
    if args.max_val_samples:
        dataset["validation"] = dataset["validation"].select(range(min(args.max_val_samples, len(dataset["validation"]))))

    tokenizer = AutoTokenizer.from_pretrained(args.sft_adapter, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    quantization_config = None
    if args.use_4bit:
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )

    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=quantization_config,
        device_map="auto",
        dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        trust_remote_code=True,
    )
    base.config.use_cache = False
    model = PeftModel.from_pretrained(base, args.sft_adapter, is_trainable=True)
    if args.gradient_checkpointing:
        model.gradient_checkpointing_enable()

    training_args = DPOConfig(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        logging_steps=5,
        save_strategy="epoch",
        eval_strategy="epoch",
        save_total_limit=2,
        bf16=torch.cuda.is_available(),
        fp16=False,
        optim="paged_adamw_8bit" if args.use_4bit else "adamw_torch",
        report_to="none",
        remove_unused_columns=False,
        beta=args.beta,
        max_length=args.max_length,
    )

    trainer = DPOTrainer(
        model=model,
        ref_model=None,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        processing_class=tokenizer,
    )
    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    print(f"Saved DPO adapter and tokenizer to: {args.output_dir}")


if __name__ == "__main__":
    main()
