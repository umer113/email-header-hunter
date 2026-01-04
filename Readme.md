# 🛡️ Email Header Hunter

**AI-Based Phishing Detection Using Email Headers**

---

## Overview

**Email Header Hunter** is a Final Year Project (FYP) that detects phishing emails by analyzing **email headers and embedded URLs** using a hybrid approach:

- Email-security rule checks (SPF, DKIM, DMARC)
- Machine learning (DistilBERT)
- AI-based (LLM) reasoning for contextual understanding
- Explainable results via an interactive interface

The system focuses on **transparent phishing detection**, helping users understand why an email is classified as phishing or legitimate.

---

## Key Features

- 🔍 **Header Analysis** – SPF, DKIM, DMARC validation  
- 🌐 **URL & Domain Checks** – suspicious links and sender domains  
- 🤖 **ML Classification** – DistilBERT-based phishing detection  
- 🧠 **AI Reasoning Agent** – independently analyzes social-engineering intent  
- 📊 **Explainable Output** – clear risk indicators and confidence scores  
- 🖥️ **Interactive UI** – Streamlit-based interface  

---

## How It Works

1. Email headers, content, and embedded links are extracted  
2. Security checks and heuristic rules are applied  
3. URLs and sender domains are analyzed for suspicious behavior  
4. Machine-learning model generates a phishing probability  
5. AI Agent independently analyzes intent, language, and risk  
6. **Final decision is made using an aggregated scoring mechanism**
7. Verdict and confidence are shown to the user  
---

## Security & Ethics

- No real credentials or sensitive data stored  
- Secrets handled via environment variables  
- Built strictly for **defensive cybersecurity research**  
- Does **not** generate phishing content  

---

## How to Run

```bash
git clone https://github.com/umer113/email-header-hunter.git
cd email-header-hunter
pip install -r requirements.txt
streamlit run main.py
