import os
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
import time

# ⚙️ Correct model paths
BASE_MODEL_PATH = "C:/Users/marie/important/mistral_model"
LORA_ADAPTER_PATH = os.path.join(os.path.dirname(__file__), "models", "custom_model")
OFFLOAD_DIR = os.path.join(os.path.dirname(__file__), "offload")

# ✅ Ensure offload folder exists
os.makedirs(OFFLOAD_DIR, exist_ok=True)

# ⚙️ Load tokenizer
print("⚙️ Loading tokenizer...")
start_time = time.time()
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_PATH, trust_remote_code=True)
print(f"Tokenizer loaded in {time.time() - start_time:.2f} seconds.")

# ⚙️ Load base model
print("⚙️ Loading base model...")
start_time = time.time()
base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL_PATH,
    device_map="auto",
    offload_folder=OFFLOAD_DIR,
    offload_buffers=True,
    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
    trust_remote_code=True
)
print(f"Base model loaded in {time.time() - start_time:.2f} seconds.")

# ⚙️ Load LoRA adapter
print("⚙️ Loading LoRA adapter...")
start_time = time.time()
model = PeftModel.from_pretrained(
    base_model,
    LORA_ADAPTER_PATH,
    device_map="auto",
    offload_folder=OFFLOAD_DIR,
    offload_buffers=True,
    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
)
print(f"LoRA adapter loaded in {time.time() - start_time:.2f} seconds.")
# Set model to eval mode
model.eval()

# ✅ Define the response function
def generate_response(prompt: str) -> str:
    print("🧠 Prompt received:", prompt)
    formatted_prompt = f"""### Vulnerability:
Description:

    {prompt}

### Mitigation:"""
    input_ids = tokenizer(formatted_prompt, return_tensors="pt").input_ids.to(model.device)
    print("🚀 Launching generation...")
    outputs = model.generate(
        input_ids=input_ids,
        max_new_tokens=128,
        temperature=0.7,
        top_p=0.95,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id
    )
    print("✅ Generation done.")
    output = tokenizer.decode(outputs[0], skip_special_tokens=True)
    mitigation = output.split("### Mitigation:")[-1].split("###")[0].strip()

    # Optional cleanup: remove echoes of the vulnerability if any
    if mitigation.startswith("Vulnerability:") or mitigation.startswith("Description:"):
        mitigation = mitigation.split("Description:")[-1].strip()
    print("📤 Returning answer:", mitigation)
    return mitigation

