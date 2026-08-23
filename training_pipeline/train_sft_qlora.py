import argparse
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig, PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune Mistral with SFT QLoRA.")
    parser.add_argument("--model", required=True, help="HF repo id or local model path.")
    parser.add_argument("--initial-adapter", default=None, help="Optional existing LoRA adapter to continue training.")
    parser.add_argument("--train-file", default="data/curated/train.jsonl")
    parser.add_argument("--val-file", default="data/curated/val.jsonl")
    parser.add_argument("--output-dir", default="models/mitigllm-mistral-sft")
    parser.add_argument("--max-seq-length", type=int, default=1024)
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-4)
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

    tokenizer_source = args.initial_adapter or args.model
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_source, trust_remote_code=True)
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

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=quantization_config,
        device_map="auto",
        dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        trust_remote_code=True,
    )
    model.config.use_cache = False
    peft_config = None
    if args.initial_adapter:
        model = PeftModel.from_pretrained(model, args.initial_adapter, is_trainable=True)
    if args.gradient_checkpointing:
        model.gradient_checkpointing_enable()

    if peft_config is None and not args.initial_adapter:
        peft_config = LoraConfig(
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=[
                "q_proj",
                "v_proj",
            ],
        )

    training_args = SFTConfig(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        logging_steps=10,
        save_strategy="epoch",
        eval_strategy="epoch",
        save_total_limit=2,
        bf16=torch.cuda.is_available(),
        fp16=False,
        optim="paged_adamw_8bit" if args.use_4bit else "adamw_torch",
        report_to="none",
        remove_unused_columns=True,
        dataset_text_field="text",
        max_length=args.max_seq_length,
        packing=False,
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        peft_config=peft_config,
    )

    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    print(f"Saved adapter and tokenizer to: {args.output_dir}")


if __name__ == "__main__":
    main()
