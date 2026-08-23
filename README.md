# MitigLLM

MitigLLM is a Purple Team cybersecurity assistant that generates practical mitigation plans from vulnerability descriptions. The project combines a React chat interface, a Django REST backend, and a locally fine-tuned Mistral 7B adapter trained with QLoRA.

The goal is not to produce generic security advice. The assistant is optimized to return structured, defensive guidance covering remediation, hardening, compensating controls, detection, validation, and residual-risk documentation.

## Features

- Vulnerability-to-mitigation generation for common security classes such as SQL injection, XSS, SSRF, path traversal, command injection, privilege escalation, DoS, crypto issues, and supply-chain risks.
- React chat interface with authentication, chat history, and guest-style direct model interaction.
- Django REST API with JWT authentication and model inference endpoint.
- Local Mistral 7B LoRA adapter loading with 4-bit quantization for limited GPU memory.
- Guardrails for non-cyber prompts, greetings, empty prompts, hallucinated CVEs, and invented version evidence.
- Training pipeline for dataset curation, SFT, LLM-as-a-judge evaluation, and DPO preference tuning.

## Architecture

```text
frontend/                  React application
backend/chatbot/            Django REST API
training_pipeline/          Dataset, evaluation, SFT, judge, and DPO scripts
docs/                       Fine-tuning notes and methodology
```

Runtime flow:

```text
User prompt
-> React chat UI
-> Django REST API
-> MitigLLM inference wrapper
-> Mistral-7B-Instruct-v0.3 + LoRA adapter
-> structured mitigation response
```

## Model Pipeline

The final training workflow used for this version:

```text
Mistral-7B-Instruct-v0.3
-> SFT v1 on curated vulnerability mitigation data
-> rule-based cyber audit
-> LLM-as-a-judge evaluation with Mistral-NeMo
-> DPO v1/v2 experiments
-> SFT specificity v2
-> DPO specificity v3
```

The final selected adapter is:

```text
models/mitigllm-mistral-dpo-specificity-v3
```

Large model files, datasets, reports, and local artifacts are intentionally ignored by Git. Keep them locally or publish them separately through a model registry if needed.

## Evaluation Summary

Evaluation was done on 50 held-out prompts using a rule-based audit and a local LLM-as-a-judge.

| Stage | Pass rate | DPO-ready | Specificity | Safety | Hallucination control |
| --- | ---: | ---: | ---: | ---: | ---: |
| SFT v1 | 0.32 | 16/50 | 3.32 | 5.00 | 5.00 |
| SFT specificity v2 | 0.32 | 16/50 | 3.50 | 5.00 | 5.00 |
| DPO specificity v3 | 0.38 | 19/50 | 3.54 | 5.00 | 5.00 |

The main improvement is specificity while keeping defensive safety and hallucination control stable.

## Backend Setup

From the project root:

```powershell
cd backend\chatbot
python -m pip install -r requirements-web.txt
python manage.py migrate
```

Run the backend with the local base model and final adapter:

```powershell
$env:MITIGLLM_BASE_MODEL_PATH="C:\Users\user\Desktop\models\Mistral-7B-Instruct-v0.3"
$env:MITIGLLM_ADAPTER_PATH="C:\Users\user\Desktop\MitigLLM\models\mitigllm-mistral-dpo-specificity-v3"
$env:MITIGLLM_OFFLOAD_DIR="C:\Users\user\Desktop\MitigLLM\backend\chatbot\offload"
python manage.py runserver 127.0.0.1:8000
```

Backend URL:

```text
http://localhost:8000/api
```

The root path `http://localhost:8000/` is not a page. Use the React frontend for the application UI.

## Frontend Setup

Open a second terminal:

```powershell
cd frontend
npm install
npm start
```

Frontend URL:

```text
http://localhost:3000
```

For production build validation:

```powershell
npm run build
```

## API Smoke Test

```powershell
Invoke-RestMethod http://localhost:8000/api/chat/ `
  -Method POST `
  -ContentType 'application/json' `
  -Body '{"prompt":"A file download endpoint receives a filename parameter and joins it directly with the storage path. An attacker can use ../ to read files outside the folder. What are the mitigations?"}'
```

Expected behavior: the model should classify the issue as path traversal and recommend canonicalization, base-directory restrictions, symlink protections, traversal payload tests, monitoring, and validation.

## Training Scripts

Key scripts:

```text
training_pipeline/build_curated_dataset.py
training_pipeline/train_sft_qlora.py
training_pipeline/evaluate_adapter.py
training_pipeline/llm_as_judge.py
training_pipeline/build_sft_from_preferences.py
training_pipeline/build_dpo_specificity_dataset.py
training_pipeline/train_dpo_qlora.py
training_pipeline/audit_cyber_outputs.py
```

Example SFT command:

```powershell
python training_pipeline\train_sft_qlora.py `
  --model C:\Users\user\Desktop\models\Mistral-7B-Instruct-v0.3 `
  --train-file data\curated\train.jsonl `
  --val-file data\curated\val.jsonl `
  --output-dir models\mitigllm-mistral-sft `
  --use-4bit `
  --gradient-checkpointing
```

Example DPO command:

```powershell
python training_pipeline\train_dpo_qlora.py `
  --base-model C:\Users\user\Desktop\models\Mistral-7B-Instruct-v0.3 `
  --sft-adapter C:\Users\user\Desktop\MitigLLM\models\mitigllm-mistral-sft-specificity-v2 `
  --train-file data\preferences\dpo_specificity_v3_train.jsonl `
  --val-file data\preferences\dpo_specificity_v3_val.jsonl `
  --output-dir models\mitigllm-mistral-dpo-specificity-v3 `
  --use-4bit `
  --gradient-checkpointing `
  --epochs 2 `
  --batch-size 1 `
  --grad-accum 4 `
  --lr 8e-6
```

## Notes

- Full RLHF/PPO was not used in this version. DPO was selected as a lighter and more stable preference-optimization method for the available hardware.
- The current model is specialized for defensive mitigation generation. For greetings or vague messages, the backend returns a short clarification instead of forcing a mitigation plan.
- This is a research and engineering prototype, not a replacement for expert security review.
