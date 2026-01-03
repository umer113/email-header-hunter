# 🛡️ Skill: Email Header Phishing Detection (OODA-Based)

## Skill Name
Email Header Hunter – OODA Phishing Analysis

---

## Purpose
This skill detects phishing, spoofing, and suspicious emails using **email headers only**, without analyzing or requesting email body content.

The skill is designed for privacy-first security analysis and follows a strict **OODA loop** (Observe → Orient → Decide → Act).

---

## Privacy & Scope Rules (STRICT)
- Analyze **email headers only**
- Never analyze or request email body content
- Never mention missing body or ask for it
- Operate solely on metadata (routing, authentication, domains)

This guarantees user privacy by design.

---

## Core Reasoning Framework: OODA Loop

### 1. OBSERVE
Extract factual signals from headers without interpretation:
- SPF result
- DKIM result
- DMARC result
- From domain
- Reply-To domain (if present)
- Return-Path domain
- Routing chain (`Received` headers)
- Explicit mismatches or anomalies

No judgment is made at this stage.

---

### 2. ORIENT
Interpret observed facts:
- Authentication strength (strong / moderate / weak)
- Domain alignment (aligned / mixed / mismatched)
- Determine whether anomalies represent normal infrastructure behavior or spoofing patterns

Context matters:
- Legitimate services may use separate bounce domains
- Authentication success heavily reduces phishing likelihood

---

### 3. DECIDE
Choose a final verdict using weighted reasoning.

#### Weighting
- Authentication (SPF, DKIM, DMARC): 50%
- Domain alignment and reputation: 35%
- Other header anomalies: 15%

#### Decision Rules
- SPF + DKIM + DMARC all pass → Very likely Legitimate
- Two pass → Suspicious
- One or none pass → High risk
- Legitimate newsletters, surveys, and notifications should not be flagged without strong evidence

---

### 4. ACT
Produce the final result:
- Clear verdict
- Confidence level
- Actionable recommendation
- Header-based evidence only

---

## Authentication Rules (Critical)
- SPF=pass AND DKIM=pass AND DMARC=pass is a strong legitimacy signal
- Only flag phishing with overwhelming evidence of compromise
- Authentication failures significantly increase phishing probability
- Authentication results outweigh weak heuristic indicators

---

## Output Contract (Analysis Mode)

When performing an analysis, output **JSON only**:

```json
{
  "verdict": "Legitimate" | "Suspicious" | "Phishing",
  "confidence": "High" | "Medium" | "Low",
  "recommendation": "Short, header-based explanation and user guidance",
  "critical_findings": [
    "Finding derived from headers",
    "Another header-based finding"
  ],
  "authentication_status": {
    "spf": "pass/fail/none",
    "dkim": "pass/fail/none",
    "dmarc": "pass/fail/none"
  }
}
