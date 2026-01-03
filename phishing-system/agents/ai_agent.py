from phi.agent import Agent
from phi.model.groq import Groq
from phi.model.openai import OpenAIChat

import json
from typing import Dict, Any, Optional
import re
import os
import sys
from dotenv import load_dotenv
load_dotenv()

def debug_log(message: str):
    print(f"[DEBUG] {message}", file=sys.stderr, flush=True)

debug_log("AI Agent module loaded!")

def load_skill_md(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"skill.md not found at: {os.path.abspath(path)}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

ENHANCED_SYSTEM_PROMPT = load_skill_md("./skills/agent_skill.md")

class PhishingDetector:
    
    def __init__(
        self, 
        # model_id: str = "gpt-4o-mini",
        model_id: str = "llama-3.3-70b-versatile",
    ):
        self.agent = Agent(
            name="Phishing Detection Specialist",
            # model=Groq(
            #     id=model_id,
            #     api_key=os.environ.get("GROQ_API_KEY")
            # ),
            model=OpenAIChat(
                model_name="gpt-4o-mini",    
                api_key=os.environ.get("OPENAI_API_KEY")
            ),
            instructions=ENHANCED_SYSTEM_PROMPT,
            add_history_to_messages=True,
            num_history_responses=5,
            markdown=False,
            structured_outputs=True,
            show_tool_calls=False,
            debug_mode=False,
        )

    def analyze(
        self, 
        headers: str, 
        # body: Optional[str] = None,
        query: Optional[str] = None
    ) -> Dict[str, Any]:

        debug_log(f"ANALYZE METHOD CALLED - Query: {query}")


        context_parts = ["=== EMAIL HEADERS ===", headers]
        
        # if body:
        #     context_parts.extend(["", "=== EMAIL BODY ===", body])
        
        context = "\n".join(context_parts)
        
        if query:
            message = f"{context}\n\n=== QUERY ===\n{query}"
        else:
            message = f"{context}\n\n=== QUERY ===\nAnalyze this email for phishing threats."
        
        response = self.agent.run(message, stream=False)
        
        try:
            # Get content from response
            if hasattr(response, 'content'):
                content = response.content.strip()
            else:
                content = str(response).strip()
            
            # Remove markdown headers
            content = re.sub(r'^#+\s+.*$', '', content, flags=re.MULTILINE)
            
            # Clean up code block markers if present
            content = content.replace("```json", "").replace("```", "").strip()
            
            # Extract JSON object from content
            start = content.find('{')
            end = content.rfind('}')
            
            # 
            if start != -1 and end != -1:
                content = content[start:end+1]
            
            # Parse JSON
            result = json.loads(content)
            return result
            
        except (json.JSONDecodeError, AttributeError, TypeError) as e:
            return {
                "verdict": "⚠️ Error",
                "response": str(response.content if hasattr(response, 'content') else response),
                "type": "text",
                "error": str(e)
            }
        
    def chat(
        self, 
        headers: str, 
        # body: str,
        question: str,
        initial_analysis: Optional[Dict[str, Any]] = None,
        conversation_history: list = None
    ) -> str:

        debug_log("=" * 80)
        debug_log(f"CHAT METHOD CALLED")
        debug_log(f"Question: {question}")
        debug_log(f"Initial analysis: {initial_analysis}")
        debug_log("=" * 80)
        
        context_parts = ["=== EMAIL HEADERS ===", headers]
        
        # if body:
        #     context_parts.extend(["", "=== EMAIL BODY ===", body])
        
        if initial_analysis:
            context_parts.append("\n=== INITIAL SECURITY ANALYSIS ===")
            context_parts.append(f"Verdict: {initial_analysis.get('verdict', 'Unknown')}")
            context_parts.append(f"Recommendation: {initial_analysis.get('recommendation', 'N/A')}")
            
            if 'critical_findings' in initial_analysis:
                context_parts.append(f"Critical Findings: {', '.join(initial_analysis['critical_findings'])}")
            
            if 'authentication_status' in initial_analysis:
                auth = initial_analysis['authentication_status']
                context_parts.append(f"Authentication: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')}")
        
        if conversation_history:
            context_parts.append("\n=== PREVIOUS CONVERSATION ===")
            for msg in conversation_history[-4:]:
                role = msg['role'].upper()
                content = msg['content']
                context_parts.append(f"{role}: {content}")
        
        context = "\n".join(context_parts)
        chat_instruction = f"""
    === USER QUESTION ===
    {question}

    === CRITICAL INSTRUCTIONS ===
    You MUST respond in PLAIN ENGLISH ONLY.

    FORBIDDEN: JSON, curly braces {{}}, structured data, code blocks

    REQUIRED: 2-4 natural English sentences explaining your answer.

    EXAMPLE CORRECT:
    "This email is suspicious because the return path domain 'bounce.surveylama.com' doesn't match the sender domain 'mr-survey.com'. While authentication passed, using different domains for bounce handling can indicate spoofing."

    ANSWER NOW IN PLAIN ENGLISH:
    """
        
        # TRY UP TO 3 TIMES
        max_attempts = 3
        
        for attempt in range(max_attempts):
            message = f"{context}\n\n{chat_instruction}"
            
            original_structured = self.agent.structured_outputs
            self.agent.structured_outputs = False
            
            response = self.agent.run(message, stream=False)
            
            self.agent.structured_outputs = original_structured
            
            if hasattr(response, 'content'):
                text = response.content.strip()
            else:
                text = str(response).strip()
            
            is_json = text.startswith('{') and ('"verdict"' in text or '"reason"' in text)
            
            if not is_json:
                text = text.replace("```json", "").replace("```", "").strip()
                text = text.replace('\\"', '"').replace('\\n', ' ').strip()
                return text
            
            try:
                data = json.loads(text.replace("```json", "").replace("```", ""))
                text = (data.get('explanation') or 
                    data.get('answer') or 
                    data.get('response') or
                    data.get('recommendation') or 
                    data.get('reason') or '')
                
                if text and len(text) > 20:
                    # Got decent text from JSON
                    return text.replace('\\"', '"').replace('\\n', ' ').strip()
            except:
                pass
            
            if attempt < max_attempts - 1:
                chat_instruction = f"""
    CRITICAL: Your last response was in JSON format. That is WRONG.

    USER QUESTION: {question}

    You must answer in PLAIN ENGLISH SENTENCES ONLY. NO JSON. NO CURLY BRACES.

    Just write 2-3 sentences like you're explaining to a friend.

    ANSWER IN PLAIN ENGLISH NOW:
    """
        
        return "I apologize, but I'm having difficulty providing a properly formatted response. The email authentication checks passed (SPF, DKIM, DMARC), but there are some domain discrepancies worth noting. Could you ask a more specific question?"