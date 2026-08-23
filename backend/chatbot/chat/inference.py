import os
import re
from functools import lru_cache
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_ADAPTER_PATH = BASE_DIR / "models" / "custom_model"
DEFAULT_OFFLOAD_DIR = BASE_DIR / "offload"
INSTRUCTION = (
    "You are MitigLLM, a Purple Team cybersecurity assistant. "
    "Given a vulnerability description, write practical mitigation guidance for a security analyst. "
    "Use concrete actions: patching, configuration, compensating controls, detection, and validation. "
    "Do not invent CVE IDs, product names, or fixed versions."
)


def _fallback_response(prompt: str) -> str:
    return (
        "Le modele local n'est pas encore charge. "
        "En attendant la configuration du fine-tuning, voici une base de mitigation: "
        "identifier les composants impactes, verifier la version vulnerable, appliquer le correctif editeur, "
        "limiter l'exposition reseau, renforcer les controles d'acces, surveiller les logs et documenter les indicateurs d'exploitation."
    )


def _chat_guardrail(prompt: str) -> str | None:
    normalized = re.sub(r"\s+", " ", prompt.lower()).strip(" .,!?")
    greetings = {
        "hi",
        "hello",
        "hey",
        "salut",
        "bonjour",
        "bonsoir",
        "slt",
        "cc",
    }
    if normalized in greetings:
        return (
            "Bonjour. Je suis MitigLLM, un assistant Purple Team specialise dans les mitigations cyber. "
            "Envoie-moi une description de vulnerabilite, une CVE, ou un scenario d'attaque defensif, "
            "et je te retournerai un plan de mitigation structure."
        )

    cyber_terms = [
        "vulnerab",
        "cve-",
        "exploit",
        "attack",
        "attacker",
        "mitigation",
        "sql",
        "xss",
        "csrf",
        "ssrf",
        "rce",
        "injection",
        "traversal",
        "overflow",
        "privilege",
        "authentication",
        "authorization",
        "endpoint",
        "patch",
        "malware",
        "dos",
        "denial of service",
        "tls",
        "certificate",
        "dependency",
        "package",
    ]
    if len(normalized) < 25 and not any(term in normalized for term in cyber_terms):
        return (
            "Je peux t'aider, mais j'ai besoin d'un contexte cyber. "
            "Donne une description de vulnerabilite, par exemple: "
            "`SQL injection in a login form using string concatenation`."
        )
    return None


def _extract_versions(text: str) -> set[str]:
    return set(re.findall(r"(?<![A-Za-z0-9])(?:>=|<=|>|<|=)?\s*v?\d+(?:\.\d+){1,3}(?![A-Za-z0-9])", text))


def _postprocess_response(prompt: str, answer: str) -> str:
    prompt_versions = _extract_versions(prompt)
    answer_versions = _extract_versions(answer)
    invented_versions = answer_versions - prompt_versions
    if invented_versions and not prompt_versions:
        answer = re.sub(
            r"\n- Preserve the version evidence from the prompt[^\n]*",
            "\n- The prompt does not provide version evidence, so avoid inventing affected or fixed versions.",
            answer,
        )
    return answer.strip()


@lru_cache(maxsize=1)
def _load_model():
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    base_model_path = os.environ.get("MITIGLLM_BASE_MODEL_PATH")
    adapter_path = Path(os.environ.get("MITIGLLM_ADAPTER_PATH", DEFAULT_ADAPTER_PATH))
    offload_dir = Path(os.environ.get("MITIGLLM_OFFLOAD_DIR", DEFAULT_OFFLOAD_DIR))
    offload_dir.mkdir(parents=True, exist_ok=True)

    if not base_model_path:
      raise FileNotFoundError(
          "MITIGLLM_BASE_MODEL_PATH is not set. Point it to the local base model directory."
      )

    base_model_path = Path(base_model_path)
    if not base_model_path.exists():
      raise FileNotFoundError(f"Base model path does not exist: {base_model_path}")

    tokenizer = AutoTokenizer.from_pretrained(str(adapter_path), trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    base_model = AutoModelForCausalLM.from_pretrained(
        str(base_model_path),
        quantization_config=quantization_config,
        device_map="auto",
        dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        trust_remote_code=True,
    )
    model = PeftModel.from_pretrained(
        base_model,
        str(adapter_path),
    )
    model.eval()
    return tokenizer, model


def generate_response(prompt: str) -> str:
    prompt = prompt.strip()
    if not prompt:
        return "Prompt vide. Ajoute une description de vulnerabilite ou une CVE."
    guarded_response = _chat_guardrail(prompt)
    if guarded_response:
        return guarded_response

    try:
        tokenizer, model = _load_model()
    except Exception as exc:
        return f"{_fallback_response(prompt)}\n\nNote technique: {exc}"

    formatted_prompt = (
        f"<s>[INST] {INSTRUCTION}\n\n"
        f"Vulnerability description:\n{prompt} [/INST]"
    )
    inputs = tokenizer(formatted_prompt, return_tensors="pt").to(model.device)
    outputs = model.generate(
        **inputs,
        max_new_tokens=260,
        temperature=0.25,
        top_p=0.9,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id,
    )
    new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
    answer = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
    return _postprocess_response(prompt, answer)
