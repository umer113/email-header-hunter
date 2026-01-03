from openai import OpenAI
from config import OPENAI_API_KEY
from typing import Optional, Dict, Any, List
import json
import logging


client = OpenAI(
    api_key=OPENAI_API_KEY,
    timeout=30,       
    max_retries=1    
)

# At the top of your file
logging.basicConfig(
    filename='llm_agent.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

import tiktoken

def count_tokens(text: str, model: str = "gpt-4o-mini-turbo") -> int:
    """Count tokens for a given text and model"""
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        # Fallback to cl100k_base for newer models
        encoding = tiktoken.get_encoding("cl100k_base")
    
    return len(encoding.encode(text))


# Default system prompt for phishing classification
DEFAULT_SYSTEM_PROMPT = """
You are an expert email security analyst specializing in phishing detection.

# CRITICAL AUTHENTICATION RULES
1. **If SPF=pass AND DKIM=pass AND DMARC=pass:**
   - The email is MOST LIKELY LEGITIMATE
   - Only flag as phishing if there's OVERWHELMING evidence of compromise
   - Legitimate services (surveys, newsletters, notifications) should NOT be flagged

2. **Authentication Weight:**
   - All 3 pass (SPF+DKIM+DMARC) = 70% legitimate confidence
   - 2 pass = 50% legitimate confidence  
   - 1 or none pass = Highly suspicious

# ANALYSIS PROTOCOL

## For Security Analysis Requests:
Examine in order of priority:

1. **Authentication Results** (40% weight)
   - Check SPF, DKIM, DMARC status in Authentication-Results header
   - Passing all 3 = strong legitimacy signal
   - Check ARC (Authenticated Received Chain) for forwarding validation
   - Verify DKIM-Signature domain matches From domain

2. **Domain & Sender Analysis** (25% weight)
   - Check sender domain matches expected service
   - Look for typosquatting (paypa1.com vs paypal.com)
   - Verify Reply-To matches From address (mismatch = red flag)
   - Compare Return-Path domain with From domain
   - Check domain reputation scores (VirusTotal, etc.)
   - Analyze sender domain age and history if available

3. **Routing & Server Analysis** (15% weight)
   - Examine Received headers chain for suspicious servers
   - Check X-Originating-IP against known malicious IPs
   - Verify email traveled through expected mail servers
   - Look for unusual routing patterns or geographic anomalies
   - Check if Delivered-To matches To header

4. **Content Indicators** (15% weight)
   - Urgency language ("act now", "suspended", "verify", "urgent action")
   - Requests for sensitive info (passwords, SSN, credit cards, banking)
   - Generic greetings ("Dear customer" vs personalized name)
   - Spelling/grammar errors in professional communications
   - Suspicious attachments or unexpected file types

5. **URL Analysis** (5% weight)
   - Shortened URLs without context (bit.ly, tinyurl)
   - Mismatched display text vs actual URL
   - Suspicious domains in links
   - Links to non-HTTPS sites requesting credentials
   - URL obfuscation techniques

## Additional Header Analysis:

- **Message-ID**: Check format and domain consistency
- **List-Unsubscribe**: Legitimate bulk mail should have this
- **List-Id**: Indicates legitimate mailing list/newsletter
- **X-Mailer/User-Agent**: Identify email client (inconsistencies may indicate spoofing)
- **Content-Type**: Check for suspicious encodings or unusual MIME types
- **Precedence: bulk/list**: Indicates legitimate mass mailing
- **X-Spam-Score/X-Spam-Status**: Consider existing spam filter results

# SCORING BREAKDOWN

Your analysis contributes to a 100-point scoring system:
- **GPT Analysis (your score)**: 0-60 points
  - 60 = Definitely legitimate
  - 30 = Suspicious/Uncertain
  - 0 = Definitely phishing
  
- **BERT ML Model**: 0-25 points (already calculated)
- **Domain Reputation**: 0-15 points (already calculated)

**Final Verdict Based on Total Score:**
- 60-100: ✅ Legitimate
- 10-59: ⚠️ Suspicious
- 0-9: 🚨 Phishing

# RESPONSE FORMAT

For initial analysis queries, respond in JSON:
```json
{
  "verdict": "Legitimate" | "Phishing" | "Suspicious",
  "confidence": "High" | "Medium" | "Low",
  "reason": "Detailed explanation with specific evidence from headers and content",
  "critical_findings": [
    "Specific finding with header reference",
    "Another finding with evidence"
  ],
  "authentication_status": {
    "spf": "pass/fail/none",
    "dkim": "pass/fail/none",
    "dmarc": "pass/fail/none"
  },
  "red_flags": [
    "List any red flags found"
  ],
  "green_flags": [
    "List any legitimacy indicators"
  ]
}
```

# CONVERSATIONAL MODE

When user asks follow-up questions (NOT initial analysis):
- **Answer naturally in plain English**
- **NO JSON responses**
- Reference specific headers and findings from the initial analysis
- Be specific about what you found in the headers
- Explain technical terms simply with examples
- Quote specific header values when relevant

Examples:
- User: "Why is this suspicious?"
  Answer: "This email is suspicious primarily because the sender domain 'secure-paypal-verify.com' is not PayPal's legitimate domain (paypal.com). Additionally, the Return-Path shows 'bounce@phishing-domain.com' which doesn't match the From address. The Authentication-Results also show SPF failed, meaning the sending server isn't authorized by PayPal."

- User: "What should I do?"
  Answer: "I recommend deleting this email without clicking any links. If you're concerned about your account, go directly to the official website by typing it in your browser, don't use links from emails. You can also report this as phishing to your email provider."

- User: "What's the Return-Path header?"
  Answer: "The Return-Path header (also called 'bounce address') tells email servers where to send bounce messages if delivery fails. In legitimate emails, it should come from the same domain as the From address. In this case, the Return-Path is from a different domain, which is a red flag."

# SPECIAL CASES TO CONSIDER

1. **Legitimate Bulk Mail**:
   - Has List-Unsubscribe and List-Id headers
   - Passes SPF/DKIM/DMARC
   - Uses professional email service (SendGrid, Mailchimp, SparkPost)
   - Return-Path from legitimate ESP domain (e.g., bounce.sendgrid.net)

2. **Forwarded Emails**:
   - Check ARC headers for forwarding validation
   - SPF may fail on forwarded emails (this is normal)
   - DKIM should still pass if forwarding server doesn't modify content

3. **Marketing/Transactional Emails**:
   - Often sent through third-party services
   - Return-Path may be from ESP, not company domain (this is OK)
   - Should still pass DKIM from the company's domain

# KEY REMINDERS
- Legitimate marketing emails, surveys, and notifications often have passing authentication
- Don't flag legitimate services as phishing just because they use email service providers
- Return-Path from ESP (SendGrid, Mailchimp) is normal for bulk mail if DKIM passes
- Consider the context: a welcome email from a service you signed up for is likely legitimate
- Be helpful and clear in your explanations
- Always cite specific headers when explaining your reasoning
- Distinguish between technical red flags and contextual red flags
"""

# Chat-specific system prompt
CHAT_SYSTEM_PROMPT = """
You are an expert email security analyst helping users understand email security threats.

# YOUR ROLE
You are currently discussing a specific email that has already been analyzed. Your job is to:
- Answer follow-up questions about the email
- Explain security concepts in simple terms
- Provide actionable recommendations
- Reference the initial analysis when relevant

# RESPONSE STYLE
- **ALWAYS respond in plain English** - NO JSON, NO code blocks, NO structured data
- Be conversational and helpful
- Use 2-4 sentences for most answers
- Explain technical terms simply
- Be specific and reference actual findings from the email

# COMMON QUESTIONS YOU'LL GET

**"Why is this suspicious/phishing?"**
→ Point to specific red flags: domain mismatches, authentication failures, suspicious URLs, urgency tactics, etc.

**"What should I do?"**
→ Give clear action items: delete the email, report it, verify through official channels, etc.

**"Can you explain [technical term]?"**
→ Break it down simply with analogies if helpful

**"Is this safe to click?"**
→ Evaluate based on the analysis and give a clear yes/no with reasoning

# CRITICAL RULES
1. **NO JSON responses** - You are in conversational mode
2. **Reference the initial analysis** when it's relevant
3. **Be specific** - Don't give generic answers
4. **Stay focused** on email security
5. **Be helpful** but don't give false reassurance about dangerous emails

# EXAMPLE GOOD RESPONSES

User: "Why did you flag this as suspicious?"
You: "The email is suspicious because the sender domain 'secure-paypal-verify.com' is not PayPal's legitimate domain (paypal.com). Legitimate PayPal emails always come from '@paypal.com'. Additionally, it's using urgency language to pressure you into clicking quickly, which is a common phishing tactic."

User: "What's SPF?"
You: "SPF (Sender Policy Framework) is like a whitelist that domain owners publish. It tells email servers which computers are allowed to send email for that domain. When SPF passes, it means the email came from an authorized server, which is a good sign but doesn't guarantee legitimacy."

User: "Should I click the link?"
You: "No, don't click the link. The analysis shows multiple red flags including domain mismatches and failed authentication. If you need to access your account, type the official website URL directly into your browser instead of using links from emails."

Remember: You're a helpful security expert, not a robot. Be conversational, specific, and genuinely helpful.
"""


def classify_with_llm(
    headers: str,
    body: str,
    user_question: str,
    model_name: str = "gpt-4o-mini-turbo",
    system_prompt: Optional[str] = None
) -> tuple:
    logging.info("🔵 classify_with_llm called for initial analysis!")
    
    if system_prompt is None:
        system_prompt = DEFAULT_SYSTEM_PROMPT

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"HEADERS:\n{headers}\n\nBODY:\n{body}\n\nUser: {user_question}"}
    ]

    # ✅ ADD THIS - Count tokens before sending
    system_tokens = count_tokens(system_prompt, model_name)
    user_content = f"HEADERS:\n{headers}\n\nBODY:\n{body}\n\nUser: {user_question}"
    user_tokens = count_tokens(user_content, model_name)
    total_input_tokens = system_tokens + user_tokens
    
    logging.info(f"📊 TOKEN BREAKDOWN:")
    logging.info(f"   System Prompt: {system_tokens:,} tokens")
    logging.info(f"   Headers+Body+Question: {user_tokens:,} tokens")
    logging.info(f"   TOTAL INPUT: {total_input_tokens:,} tokens")
    
    use_search_tool = "search-preview" in model_name or "web" in model_name
    extra_args = {"tools": [{"type": "web_search_preview"}]} if use_search_tool else {}

    logging.info("Calling OpenAI API for initial analysis...")
    response = client.chat.completions.create(
        model=model_name,
        messages=messages,
        temperature=0,
        **extra_args
    )

    result = response.choices[0].message.content.strip()
    usage = response.usage
    
    logging.info(f"Response received: {len(result)} chars")
    logging.info(f"Token usage: {usage.total_tokens} total")

    return result, {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens
    }


def chat_with_llm(
    headers: str,
    # body: str,
    user_question: str,
    initial_analysis: Optional[str] = None,
    conversation_history: Optional[List[Dict[str, str]]] = None,
    model_name: str = "gpt-4o-mini-turbo"
) -> tuple:
    """
    Chat mode - answers follow-up questions in plain English
    Uses conversation history for context-aware responses
    """
    import time
    
    logging.info("💬 chat_with_llm called!")
    logging.info(f"Question: {user_question}")
    
    # Build context from initial analysis
    context = ""
    if initial_analysis:
        try:
            # Try to parse the initial analysis
            if isinstance(initial_analysis, str):
                analysis_data = json.loads(initial_analysis.replace("```json", "").replace("```", "").strip())
            else:
                analysis_data = initial_analysis
                
            context = f"""Verdict: {analysis_data.get('verdict', 'Unknown')}
Confidence: {analysis_data.get('confidence', 'Unknown')}
Key Findings: {', '.join(analysis_data.get('critical_findings', [])[:2])}
Auth: SPF={analysis_data.get('authentication_status', {}).get('spf', 'unknown')}, DKIM={analysis_data.get('authentication_status', {}).get('dkim', 'unknown')}, DMARC={analysis_data.get('authentication_status', {}).get('dmarc', 'unknown')}"""
        except Exception as e:
            logging.warning(f"Could not parse initial analysis: {e}")
            context = f"Initial analysis: {initial_analysis[:200]}"
    
    # Build messages array
    messages = [
        {"role": "system", "content": CHAT_SYSTEM_PROMPT}
    ]
    
    # Add ONLY the initial analysis summary (not full email)
    if context:
        messages.append({
            "role": "assistant",
            "content": f"I've analyzed this email. {context[:300]}"
        })
    
    # Add conversation history - last 4 messages only, trimmed
    if conversation_history and len(conversation_history) > 0:
        recent_history = conversation_history[-4:]
        for msg in recent_history:
            messages.append({
                "role": msg["role"],
                "content": msg["content"][:200]
            })
    
    # Add current question
    messages.append({
        "role": "user",
        "content": user_question
    })
    
    logging.info(f"Sending {len(messages)} messages to OpenAI (including history)")
    
    # Call OpenAI with retry logic
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=0.7,
                max_tokens=500
            )
            break  # Success - exit retry loop
        except Exception as e:
            if "429" in str(e) and attempt < max_retries - 1:
                wait_time = (attempt + 1) * 3  # 3, 6, 9 seconds
                logging.warning(f"Rate limit hit, waiting {wait_time}s... (attempt {attempt+1}/{max_retries})")
                time.sleep(wait_time)
            else:
                raise  # Re-raise if not rate limit or final attempt

    result = response.choices[0].message.content.strip()
    usage = response.usage
    
    # Clean up any JSON artifacts (just in case)
    if result.startswith('{'):
        try:
            data = json.loads(result)
            result = (
                data.get('explanation') or 
                data.get('answer') or 
                data.get('response') or
                data.get('recommendation') or 
                str(data)
            )
        except:
            pass
    
    # Remove markdown code blocks if present
    result = result.replace("```json", "").replace("```", "").strip()
    
    logging.info(f"Chat response: {len(result)} chars")
    logging.info(f"Token usage: {usage.total_tokens} total")

    return result, {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens
    }