import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os
import email
from email import policy


MODEL_ID = "xeon1249/phishing-agent"
LABELS = {0: " Legit", 1: " Phishing"} 


model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()

def distilBert(headers, body=None):
    text = f"""
    [HEADERS]
    {headers}

    [BODY]
    {body if body else ""}
    """

    tokens = tokenizer(
        text,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=512
    )
    tokens = {k: v.to(device) for k, v in tokens.items()}

    with torch.no_grad():
        outputs = model(**tokens)
        probs = torch.nn.functional.softmax(outputs.logits, dim=1)
        pred = torch.argmax(probs, dim=1).item()

    confidence = probs[0][pred].item()
    label = LABELS.get(pred, "❓ Unknown")

    return label, confidence




def read_any_file(file_path):
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
            try:
                msg = email.message_from_bytes(raw, policy=policy.default)
                subject = msg["subject"] or ""
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body += part.get_content()
                else:
                    body = msg.get_content()
                return f"{subject} {body}"
            except Exception:
                return raw.decode("utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"❌ Could not read file: {e}")