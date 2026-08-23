# MitigLLM Fine-Tuning Pipeline

This project should not try to reproduce full pre-training from scratch. A 6T-token next-token pre-training stage is for building a foundation model and is far beyond the scope of this project.

For MitigLLM, the realistic version of the pipeline is:

```text
Mistral-7B-Instruct-v0.3
-> optional cybersecurity continued pre-training
-> SFT on vulnerability-to-mitigation examples
-> evaluation
-> preference dataset
-> DPO or reward-model training
-> optional PPO/RLAIF experiments
```

## Stage 0 - Base Model

Recommended base:

```text
mistralai/Mistral-7B-Instruct-v0.3
```

Use a local path after download:

```powershell
C:\Users\user\Desktop\models\Mistral-7B-Instruct-v0.3
```

## Stage 1 - Optional Continued Pre-Training

This is the realistic replacement for "pre-training 6T tokens".

Goal: adapt the base model to cybersecurity language using unlabeled text such as CVE descriptions, CWE pages, advisories, vendor bulletins, and mitigation guides.

Training objective:

```text
next-token prediction
```

This stage is optional. Start with SFT first.

## Stage 2 - SFT

Goal: teach the model the target behavior:

```text
vulnerability description -> clear mitigation guidance
```

Prepare the curated dataset:

```powershell
cd C:\Users\user\Desktop\MitigLLM
python training_pipeline\build_curated_dataset.py `
  --input final_fully_cleaned_and_aligned.json `
  --output-dir data\curated
```

Train with QLoRA:

```powershell
python training_pipeline\train_sft_qlora.py `
  --model C:\Users\user\Desktop\models\Mistral-7B-Instruct-v0.3 `
  --train-file data\curated\train.jsonl `
  --val-file data\curated\val.jsonl `
  --output-dir models\mitigllm-mistral-sft `
  --use-4bit `
  --gradient-checkpointing
```

## Stage 3 - Reward Model Or DPO

Reward-model training needs preference data:

```json
{
  "prompt": "CVE description...",
  "chosen": "better mitigation answer",
  "rejected": "weaker mitigation answer"
}
```

For this project, DPO is usually simpler than PPO:

```text
SFT model + preference pairs -> DPO adapter
```

Create a first preference seed file:

```powershell
python training_pipeline\make_preference_seed.py `
  --sft-file data\processed\sft_train.jsonl `
  --output data\processed\preference_seed.jsonl
```

This seed file is not a perfect human preference dataset. It is a starting point that should be reviewed or regenerated with an evaluator model before serious DPO/RM training.

## Stage 4 - PPO / REINFORCE

Use PPO only after the SFT model is stable and a reward model exists. PPO is expensive, unstable, and harder to debug.

For the first improved version of MitigLLM, do not start with PPO.

## Stage 5 - RLAIF

RLAIF can be used to generate preference labels with a stronger evaluator model. The evaluator should score answers on:

- technical correctness
- actionability
- patch or upgrade guidance
- compensating controls
- detection and monitoring
- clarity
- absence of hallucinated CVEs or versions

RLAIF should create preference data, not replace evaluation.
