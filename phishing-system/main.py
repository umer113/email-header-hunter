# Complete Phishing Email Detection System
# Single file with Upload and Gmail Dashboard functionality

import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import time
import json
import re
import tempfile
import logging
import sys

# Import your existing modules
from config import OPENAI_API_KEY, VIRUS_TOTAL_API
from agents.LLM_agent import classify_with_llm, chat_with_llm
from agents.ai_agent import PhishingDetector
from models.distilBert import distilBert
from checker.domain_checker import check_sender_domain, extract_sender_domain
from checker.url_check import extract_urls_from_body, scan_and_check_url
from agents.extractor_agent import extract_headers_and_text, extract_email_fields

# ============================================================================
# CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Email Header Hunter",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Global Settings - CHANGE ONCE HERE
USE_GROQ_AGENT = True  # Set to True to use Groq, False to use OpenAI
MODEL_NAME = "gpt-4o-mini"
BACKEND_URL = "http://localhost:8000"

logging.basicConfig(
    filename='phishing_detection.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize Groq agent
groq_agent = PhishingDetector()

def debug_log(message: str):
    print(f"[DEBUG] {message}", file=sys.stderr, flush=True)
    logging.info(message)

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

if "analysis_cache" not in st.session_state:
    st.session_state.analysis_cache = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "gmail_authenticated" not in st.session_state:
    st.session_state.gmail_authenticated = False
if "gmail_emails" not in st.session_state:
    st.session_state.gmail_emails = []
if "analyzed_emails" not in st.session_state:
    st.session_state.analyzed_emails = []
if "analysis_in_progress" not in st.session_state:
    st.session_state.analysis_in_progress = False

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def analyze_email_with_ai(headers_text, body_text, query="Is this email phishing or legitimate?"):
    """
    Analyze email using either Groq or OpenAI based on global setting
    Returns: (result_json_string, usage_dict)
    """
    if USE_GROQ_AGENT:
        st.write("✅ Using Groq Agent")
        logging.critical("🔥 GROQ AGENT SELECTED")
        
        groq_result = groq_agent.analyze(
            headers=headers_text,
            body=body_text,
            query=query
        )
        
        result_json = json.dumps(groq_result)
        usage = {"total_tokens": 0, "model": "groq"}
        
        logging.critical(f"✅ Groq result: {result_json[:200]}")
        return result_json, usage
    else:
        st.write("🔄 Using OpenAI")
        logging.critical("🔄 OPENAI SELECTED")
        
        result, usage = classify_with_llm(
            headers_text,
            body_text,
            user_question=query,
            model_name=MODEL_NAME
        )
        
        logging.critical(f"✅ OpenAI result: {result[:200] if isinstance(result, str) else str(result)[:200]}")
        return result, usage

def calculate_scores(gpt_result, headers_text, body_text, sender_domain=None):
    """
    Calculate scores from AI analysis, BERT, and domain reputation
    Returns: (total_score, gpt_score, gpt_verdict, gpt_reason, bert_score, bert_label, bert_confidence, domain_score, domain_result)
    """
    # Parse GPT/Groq result
    try:
        if isinstance(gpt_result, dict):
            gpt_json = gpt_result
        else:
            gpt_json = json.loads(gpt_result)
        
        gpt_verdict = gpt_json.get("verdict", "")
        gpt_reason = gpt_json.get("reason", "") or gpt_json.get("recommendation", "")
        
        # Check authentication status
        auth_results = headers_text.lower()
        spf_pass = "spf=pass" in auth_results or "spf: pass" in auth_results
        dkim_pass = "dkim=pass" in auth_results or "dkim: pass" in auth_results
        dmarc_pass = "dmarc=pass" in auth_results or "dmarc: pass" in auth_results
        
        verdict_lower = gpt_verdict.lower()
        
        # Scoring based on authentication and verdict
        if spf_pass and dkim_pass and dmarc_pass:
            if "phishing" in verdict_lower:
                gpt_score = 45
            else:
                gpt_score = 60
        else:
            if "legit" in verdict_lower or "legitimate" in verdict_lower:
                gpt_score = 50
            elif "phishing" in verdict_lower:
                gpt_score = 5
            else:
                gpt_score = 30
                
    except Exception as e:
        logging.error(f"Error parsing AI result: {e}")
        gpt_verdict = "❓ Could not parse result"
        gpt_reason = "Parsing failed"
        gpt_score = 30
    
    # BERT Classification
    vote_label, vote_confidence = distilBert(headers_text, body_text)
    if "phishing" in vote_label.lower():
        bert_score = int(25 * (1 - vote_confidence))
    else:
        bert_score = int(25 * vote_confidence)
    
    # Domain reputation check
    domain_score = 15
    domain_result = None
    if sender_domain:
        try:
            domain_result = check_sender_domain(sender_domain, VIRUS_TOTAL_API)
            if isinstance(domain_result, dict):
                malicious = domain_result.get("malicious", 0)
                if malicious > 5:
                    domain_score = 0
                elif malicious > 2:
                    domain_score = 5
                elif malicious > 0:
                    domain_score = 10
                else:
                    domain_score = 15
        except Exception as e:
            logging.error(f"Domain check error: {e}")
            domain_score = 10
    
    total_score = gpt_score + bert_score + domain_score
    
    return (total_score, gpt_score, gpt_verdict, gpt_reason, bert_score, 
            vote_label, vote_confidence, domain_score, domain_result)

def get_final_verdict(total_score):
    """Get final verdict based on total score"""
    if total_score >= 60:
        return "✅ Legit", "green"
    elif total_score >= 10:
        return "⚠️ Suspicious", "orange"
    else:
        return "🚨 Phishing", "red"

# ============================================================================
# SIDEBAR NAVIGATION
# ============================================================================

with st.sidebar:
    st.markdown("""
        <div style='text-align: center; margin-bottom: 30px;'>
            <h2 style='color: #1f77b4;'>🛡️ Security Hub</h2>
        </div>
    """, unsafe_allow_html=True)
    
    page = st.selectbox(
        "Select Analysis Mode",
        ["📧 Upload Email", "📬 Gmail Dashboard", "⚙️ Settings"],
        index=0
    )
    
    st.markdown("---")
    
    # Show current AI provider
    ai_provider = "🤖 Groq (Llama)" if USE_GROQ_AGENT else "🔵 OpenAI (GPT-4o-mini)"
    st.info(f"**AI Provider:** {ai_provider}")
    
    st.markdown("---")
    st.markdown("""
        <div style='padding: 15px; background-color: rgba(30, 144, 255, 0.1); border-radius: 10px;'>
            <h4 style='color: #1f77b4; margin-bottom: 10px;'>🔍 Detection Features</h4>
            <ul style='font-size: 12px; color: #666;'>
                <li>AI-Powered Analysis</li>
                <li>DistilBERT Classification</li>
                <li>Domain Reputation Check</li>
                <li>URL Safety Scanning</li>
                <li>Interactive Chat Agent</li>
            </ul>
        </div>
    """, unsafe_allow_html=True)

# ============================================================================
# PAGE: UPLOAD EMAIL ANALYSIS
# ============================================================================

if page == "📧 Upload Email":
    st.markdown("""
        <div style='text-align: center; margin-top: 20px; margin-bottom: 40px;'>
            <h1 style='color: white;'>📧 Email Upload Analysis</h1>
            <p style='color: gray; font-size: 15px;'>Upload an email file (.eml, .txt, .msg) for instant analysis</p>
        </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("", type=None, label_visibility="collapsed")
    
    if uploaded_file:
        st.session_state.analysis_cache = None
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file.read())
            email_file_path = tmp_file.name

        try:
            headers, body, _ = extract_headers_and_text(email_file_path)
            all_email_fields = extract_email_fields(email_file_path)
            sender_domain = extract_sender_domain(headers)
            urls = extract_urls_from_body(body)

            with st.spinner("Analyzing email..."):
                # Prepare headers text
                headers_text = f"""From: {all_email_fields.get('from', '')}
To: {all_email_fields.get('to', '')}
Subject: {all_email_fields.get('subject', '')}
Date: {all_email_fields.get('date', '')}
Message-ID: {all_email_fields.get('id', '')}
Reply-To: {all_email_fields.get('reply_to', '')}
Return-Path: {all_email_fields.get('return_path', '')}

=== AUTHENTICATION RESULTS ===
SPF: {all_email_fields.get('spf', 'n/a')}
DKIM: {all_email_fields.get('dkim', 'n/a')}
DMARC: {all_email_fields.get('dmarc', 'n/a')}
Authentication-Results: {all_email_fields.get('authentication_results', 'n/a')}

=== ROUTING INFORMATION ===
Received Count: {all_email_fields.get('received_count', 0)}
Delivered-To: {all_email_fields.get('delivered_to', '')}

=== SENDER DOMAIN ===
Sender Domain: {all_email_fields.get('sender_domain', 'n/a')}
Return-Path Domain: {all_email_fields.get('return_path_domain', 'n/a')}
Reply-To Domain: {all_email_fields.get('reply_to_domain', 'n/a')}
"""

                # AI Analysis
                if st.session_state.analysis_cache is None:
                    gpt_result, gpt_usage = analyze_email_with_ai(
                        headers_text,
                        body,
                        "Is this email phishing or legitimate?"
                    )
                    st.session_state.analysis_cache = (gpt_result, gpt_usage)
                else:
                    gpt_result, gpt_usage = st.session_state.analysis_cache

                # Calculate scores
                (total_score, gpt_score, gpt_verdict, gpt_reason, bert_score,
                 vote_label, vote_confidence, domain_score, domain_result) = calculate_scores(
                    gpt_result, headers_text, body, sender_domain
                )

                # URL scanning
                url_results = []
                for url in urls[:5]:
                    try:
                        url_results.append((url, scan_and_check_url(url, VIRUS_TOTAL_API)))
                    except Exception as e:
                        url_results.append((url, {"error": str(e)}))

                malicious_count = sum(
                    result.get("malicious", 0) > 0
                    for _, result in url_results
                    if isinstance(result, dict)
                )

            # Display results
            final_verdict, verdict_color = get_final_verdict(total_score)
            
            st.markdown("---")
            st.subheader("Final Verdict")
            st.markdown(f"### {final_verdict}  \n**Total Score:** `{total_score}/100`")

            show_details = st.toggle("🔎 View Full Analysis", value=False, key="analysis_toggle")

            if show_details:
                st.subheader("AI Security Analysis")
                st.markdown(f"**Verdict:** {gpt_verdict}")
                st.markdown(f"**Reasoning:** {gpt_reason}")
                st.markdown(f"**Score:** {gpt_score}/60")

                st.subheader("DistilBERT Classification")
                st.markdown(f"**{vote_label}** (Confidence: {vote_confidence:.2%})")
                st.markdown(f"**Score:** {bert_score}/25")

                st.subheader("Sender Domain Reputation")
                if sender_domain:
                    st.markdown(f"**Sender Domain:** `{sender_domain}`")
                    st.markdown(f"**Domain Score:** {domain_score}/15")
                    if isinstance(domain_result, dict):
                        st.json(domain_result)
                else:
                    st.warning("⚠️ Could not extract sender domain.")

                if url_results:
                    st.subheader("🔗 URL Safety Scan")
                    for idx, (url, result) in enumerate(url_results):
                        with st.expander(f"🔍 URL #{idx + 1}: {url}"):
                            st.markdown(f"**Scanned URL:** `{url}`")
                            if isinstance(result, dict) and "error" not in result:
                                st.write({
                                    "Malicious": result.get("malicious", 0),
                                    "Suspicious": result.get("suspicious", 0),
                                    "Harmless": result.get("harmless", 0),
                                })

                with st.expander("📊 Grading Breakdown"):
                    st.markdown(f"- AI Analysis: `{gpt_verdict}` → **{gpt_score}/60**")
                    st.markdown(f"- DistilBERT: `{vote_label}` → **{bert_score}/25**")
                    st.markdown(f"- Domain Reputation → **{domain_score}/15**")

            st.success("✅ Email analyzed successfully.")

            # Chat Interface
            st.markdown("---")
            st.subheader("💬 Ask the Security Agent")

            for msg in st.session_state.chat_history:
                st.chat_message(msg["role"]).write(msg["content"])

            user_input = st.chat_input("Ask something about this email...")

            if user_input:
                st.chat_message("user").write(user_input)
                st.session_state.chat_history.append({"role": "user", "content": user_input})

                with st.spinner("Agent is thinking..."):
                    try:
                        if USE_GROQ_AGENT:
                            # Use Groq chat
                            debug_log("💬 Using Groq chat")
                            
                            # Prepare initial analysis for Groq
                            initial_analysis_dict = None
                            try:
                                if isinstance(gpt_result, str):
                                    initial_analysis_dict = json.loads(gpt_result)
                                else:
                                    initial_analysis_dict = gpt_result
                            except:
                                pass
                            
                            response_text = groq_agent.chat(
                                headers=headers,
                                body=body,
                                question=user_input,
                                initial_analysis=initial_analysis_dict,
                                conversation_history=st.session_state.chat_history[:-1]
                            )
                            usage = {"total_tokens": 0, "model": "groq"}
                        else:
                            # Use OpenAI chat
                            debug_log("💬 Using OpenAI chat")
                            response_text, usage = chat_with_llm(
                                headers=headers,
                                body=body,
                                user_question=user_input,
                                initial_analysis=gpt_result,
                                conversation_history=st.session_state.chat_history[:-1],
                                model_name=MODEL_NAME
                            )

                        st.chat_message("assistant").write(response_text)
                        st.session_state.chat_history.append({
                            "role": "assistant",
                            "content": response_text
                        })

                        debug_log(f"✅ Got response: {response_text[:100]}...")
                        debug_log(f"📊 Token usage: {usage}")

                    except Exception as e:
                        error_msg = f"Error: {str(e)}"
                        debug_log(f"❌ Error in chat: {error_msg}")
                        st.error(error_msg)
                        
                        st.session_state.chat_history.append({
                            "role": "assistant",
                            "content": f"I apologize, but I encountered an error: {str(e)}"
                        })

                try:
                    st.rerun()
                except AttributeError:
                    st.experimental_rerun()

        except Exception as e:
            st.error(f"Error while processing email: {str(e)}")
            logging.error(f"Upload analysis error: {e}")

# ============================================================================
# PAGE: GMAIL DASHBOARD
# ============================================================================

elif page == "📬 Gmail Dashboard":
    st.markdown("""
        <div style='text-align: center; margin-top: 20px; margin-bottom: 40px;'>
            <h1 style='color: white;'>📬 Gmail Security Dashboard</h1>
            <p style='color: gray; font-size: 15px;'>Connect your Gmail account to analyze emails in bulk</p>
        </div>
    """, unsafe_allow_html=True)

    # Authentication Section
    if not st.session_state.gmail_authenticated:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("""
                <div style='text-align: center; padding: 30px; border: 2px dashed #1f77b4; border-radius: 15px;'>
                    <h3 style='color: #1f77b4;'>🔐 Secure Gmail Connection</h3>
                    <p style='color: #666;'>We use OAuth 2.0 to securely access only your email headers.</p>
                </div>
            """, unsafe_allow_html=True)

            if st.button("🔗 Connect Gmail Account", type="primary", use_container_width=True):
                auth_url = f"{BACKEND_URL}/auth/google"
                st.markdown(f'<meta http-equiv="refresh" content="0; url={auth_url}">', unsafe_allow_html=True)
                st.info("Redirecting to Gmail authentication...")

        # Handle authentication callback (compatible with all Streamlit versions)
        try:
            # Streamlit >= 1.30
            query_params = st.query_params
            if query_params.get("authenticated") == "true":
                st.session_state.gmail_authenticated = True
                st.rerun()
        except AttributeError:
            # Streamlit < 1.30
            query_params = st.experimental_get_query_params()
            if "authenticated" in query_params and query_params["authenticated"][0] == "true":
                st.session_state.gmail_authenticated = True
                try:
                    st.rerun()
                except AttributeError:
                    st.experimental_rerun()

    else:
        # Main Dashboard
        col1, col2 = st.columns([2, 1])

        with col1:
            if st.button("📥 Fetch Latest Emails", type="primary"):
                with st.spinner("Fetching emails from Gmail..."):
                    try:
                        response = requests.get(f"{BACKEND_URL}/gmail/emails")
                        if response.status_code == 200:
                            data = response.json()
                            st.session_state.gmail_emails = data.get("emails", [])
                            st.success(f"✅ Fetched {len(st.session_state.gmail_emails)} emails!")
                        else:
                            st.error("❌ Failed to fetch emails.")
                    except Exception as e:
                        st.error(f"❌ Connection error: {str(e)}")

        with col2:
            if st.button("🔄 Disconnect Gmail", type="secondary"):
                st.session_state.gmail_authenticated = False
                st.session_state.gmail_emails = []
                st.session_state.analyzed_emails = []
                st.success("✅ Gmail account disconnected!")
                try:
                    st.rerun()
                except AttributeError:
                    st.experimental_rerun()

        # Email Analysis Section
        if st.session_state.gmail_emails:
            st.markdown("---")
            st.subheader("📧 Email Analysis")

            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                if st.button("🔍 Analyze All Emails", disabled=st.session_state.analysis_in_progress):
                    st.session_state.analysis_in_progress = True

                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    analyzed_results = []
                    total_emails = len(st.session_state.gmail_emails)

                    for i, email_data in enumerate(st.session_state.gmail_emails):
                        status_text.text(f"Analyzing email {i+1} of {total_emails}...")
                        progress_bar.progress((i + 1) / total_emails)

                        try:
                            headers_text = f"""From: {email_data.get('from', '')}
To: {email_data.get('to', '')}
Subject: {email_data.get('subject', '')}
Date: {email_data.get('date', '')}
Reply-To: {email_data.get('reply_to', '')}
Return-Path: {email_data.get('return_path', '')}
SPF: {email_data.get('spf', 'n/a')}
DKIM: {email_data.get('dkim', 'n/a')}
DMARC: {email_data.get('dmarc', 'n/a')}
"""

                            body_text = ""
                            sender_domain = None
                            if email_data.get('from'):
                                match = re.search(r'@([a-zA-Z0-9.-]+)', email_data['from'])
                                if match:
                                    sender_domain = match.group(1)

                            # AI Analysis
                            gpt_result, gpt_usage = analyze_email_with_ai(
                                headers_text,
                                body_text,
                                "Based on these email headers, is this email phishing or legitimate?"
                            )

                            # Calculate scores
                            (total_score, gpt_score, gpt_verdict, gpt_reason, bert_score,
                             vote_label, vote_confidence, domain_score, domain_result) = calculate_scores(
                                gpt_result, headers_text, body_text, sender_domain
                            )

                            final_verdict, verdict_color = get_final_verdict(total_score)

                            analyzed_results.append({
                                "id": email_data.get("id", f"email_{i}"),
                                "date": email_data.get("date", ""),
                                "from": email_data.get("from", ""),
                                "subject": email_data.get("subject", ""),
                                "verdict": final_verdict,
                                "verdict_color": verdict_color,
                                "total_score": total_score,
                                "gpt_verdict": gpt_verdict,
                                "gpt_reason": gpt_reason,
                                "gpt_score": gpt_score,
                                "bert_label": vote_label,
                                "bert_confidence": vote_confidence,
                                "bert_score": bert_score,
                                "domain_score": domain_score,
                                "domain_result": domain_result,
                                "sender_domain": sender_domain,
                                "spf": email_data.get("spf", "n/a"),
                                "dkim": email_data.get("dkim", "n/a"),
                                "dmarc": email_data.get("dmarc", "n/a"),
                            })

                        except Exception as e:
                            logging.error(f"Analysis error for email {i}: {e}")
                            analyzed_results.append({
                                "id": email_data.get("id", f"email_{i}"),
                                "date": email_data.get("date", ""),
                                "from": email_data.get("from", ""),
                                "subject": email_data.get("subject", ""),
                                "verdict": "❌ Error",
                                "verdict_color": "gray",
                                "error": str(e)
                            })

                        time.sleep(1)  # Rate limiting

                    st.session_state.analyzed_emails = analyzed_results
                    st.session_state.analysis_in_progress = False

                    progress_bar.progress(1.0)
                    status_text.text("✅ Analysis complete!")
                    st.success(f"✅ Analyzed {len(analyzed_results)} emails!")
                    try:
                        st.rerun()
                    except AttributeError:
                        st.experimental_rerun()

            with col2:
                if st.button("🗑️ Clear Results"):
                    st.session_state.analyzed_emails = []
                    st.success("Results cleared!")
                    try:
                        st.rerun()
                    except AttributeError:
                        st.experimental_rerun()

            # Show raw headers
            with st.expander("📋 View Raw Email Headers", expanded=False):
                if st.session_state.gmail_emails:
                    df = pd.DataFrame(st.session_state.gmail_emails)
                    st.dataframe(df, use_container_width=True)

        # Display Analysis Results
        if st.session_state.analyzed_emails:
            st.markdown("---")
            st.subheader("📊 Email Security Dashboard")

            total_emails = len(st.session_state.analyzed_emails)
            legit_count = sum(1 for e in st.session_state.analyzed_emails if "Legit" in e.get("verdict", ""))
            suspicious_count = sum(1 for e in st.session_state.analyzed_emails if "Suspicious" in e.get("verdict", ""))
            phishing_count = sum(1 for e in st.session_state.analyzed_emails if "Phishing" in e.get("verdict", ""))

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("📧 Total", total_emails)
            with col2:
                st.metric("✅ Legit", legit_count)
            with col3:
                st.metric("⚠️ Suspicious", suspicious_count)
            with col4:
                st.metric("🚨 Phishing", phishing_count)

            # Email table
            st.markdown("### 📋 Analysis Results")
            display_data = []
            for email in st.session_state.analyzed_emails:
                display_data.append({
                    "Date": email.get("date", "")[:16],
                    "From": email.get("from", "")[:50],
                    "Subject": email.get("subject", "")[:60],
                    "Verdict": email.get("verdict", ""),
                    "Score": f"{email.get('total_score', 0)}/100",
                })

            if display_data:
                df = pd.DataFrame(display_data)
                st.dataframe(df, use_container_width=True)

                # Detailed analysis for selected email
                st.markdown("### 🔍 Detailed Email Analysis")
                selected_email_index = st.selectbox(
                    "Select email for detailed analysis:",
                    range(len(st.session_state.analyzed_emails)),
                    format_func=lambda x: f"{st.session_state.analyzed_emails[x].get('subject', 'No Subject')[:80]}..."
                )

                if selected_email_index is not None:
                    selected_email = st.session_state.analyzed_emails[selected_email_index]
                    
                    # Email header info
                    st.markdown("---")
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.markdown(f"**From:** {selected_email.get('from', 'N/A')}")
                        st.markdown(f"**Subject:** {selected_email.get('subject', 'N/A')}")
                        st.markdown(f"**Date:** {selected_email.get('date', 'N/A')}")
                    with col2:
                        verdict = selected_email.get('verdict', 'Unknown')
                        score = selected_email.get('total_score', 0)
                        st.markdown(f"### {verdict}")
                        st.markdown(f"**Score:** {score}/100")

                    # Detailed analysis tabs (removed Chat tab)
                    tab1, tab2, tab3 = st.tabs(["🤖 AI Analysis", "🔒 Authentication", "🌐 Domain Check"])

                    with tab1:
                        st.subheader("AI Security Analysis")
                        st.markdown(f"**Verdict:** {selected_email.get('gpt_verdict', 'N/A')}")
                        st.markdown(f"**Reasoning:** {selected_email.get('gpt_reason', 'N/A')}")
                        st.markdown(f"**Score:** {selected_email.get('gpt_score', 0)}/60")
                        
                        st.subheader("DistilBERT Classification")
                        st.markdown(f"**Label:** {selected_email.get('bert_label', 'N/A')}")
                        st.markdown(f"**Confidence:** {selected_email.get('bert_confidence', 0):.2%}")
                        st.markdown(f"**Score:** {selected_email.get('bert_score', 0)}/25")
                        
                        st.subheader("📊 Grading Breakdown")
                        st.markdown(f"- **AI Analysis:** `{selected_email.get('gpt_verdict', 'N/A')}` → **{selected_email.get('gpt_score', 0)}/60**")
                        st.markdown(f"- **DistilBERT:** `{selected_email.get('bert_label', 'N/A')}` (Confidence: {selected_email.get('bert_confidence', 0):.2%}) → **{selected_email.get('bert_score', 0)}/25**")
                        st.markdown(f"- **Domain Reputation:** → **{selected_email.get('domain_score', 0)}/15**")
                        st.markdown(f"- **Total Score:** **{selected_email.get('total_score', 0)}/100**")

                    with tab2:
                        st.subheader("Email Authentication Results")
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            spf_status = selected_email.get('spf', 'n/a')
                            spf_color = "green" if spf_status == "pass" else "red" if spf_status == "fail" else "gray"
                            st.markdown(f"**SPF:** <span style='color:{spf_color}'>{spf_status.upper()}</span>", unsafe_allow_html=True)
                        
                        with col2:
                            dkim_status = selected_email.get('dkim', 'n/a')
                            dkim_color = "green" if dkim_status == "pass" else "red" if dkim_status == "fail" else "gray"
                            st.markdown(f"**DKIM:** <span style='color:{dkim_color}'>{dkim_color.upper()}</span>", unsafe_allow_html=True)
                        
                        with col3:
                            dmarc_status = selected_email.get('dmarc', 'n/a')
                            dmarc_color = "green" if dmarc_status == "pass" else "red" if dmarc_status == "fail" else "gray"
                            st.markdown(f"**DMARC:** <span style='color:{dmarc_color}'>{dmarc_status.upper()}</span>", unsafe_allow_html=True)

                        st.markdown("---")
                        st.markdown("""
                        **Authentication Explanation:**
                        - **SPF**: Verifies the sender's IP is authorized to send email for this domain
                        - **DKIM**: Cryptographic signature confirms email hasn't been tampered with
                        - **DMARC**: Policy that tells receiving servers what to do with emails that fail SPF/DKIM
                        """)

                    with tab3:
                        st.subheader("Domain Reputation Analysis")
                        sender_domain = selected_email.get('sender_domain')
                        if sender_domain:
                            st.markdown(f"**Sender Domain:** `{sender_domain}`")
                            st.markdown(f"**Domain Score:** {selected_email.get('domain_score', 'N/A')}/15")
                            
                            domain_result = selected_email.get('domain_result')
                            if domain_result and isinstance(domain_result, dict):
                                st.markdown("**VirusTotal Analysis:**")
                                st.json(domain_result)
                            else:
                                st.info("Domain reputation data not available")
                        else:
                            st.warning("Could not extract sender domain from this email")

                    # Chat section moved OUTSIDE of tabs
                    st.markdown("---")
                    st.subheader("💬 Chat with Security Agent")
                    
                    # Initialize chat history for this specific email
                    chat_key = f"gmail_chat_{selected_email.get('id', 'unknown')}"
                    if chat_key not in st.session_state:
                        st.session_state[chat_key] = []

                    # Display chat history
                    for msg in st.session_state[chat_key]:
                        st.chat_message(msg["role"]).write(msg["content"])

                    user_input = st.chat_input("Ask questions about this email analysis...")

                    if user_input:
                        st.session_state[chat_key].append({"role": "user", "content": user_input})

                        with st.spinner("Security agent is analyzing..."):
                            try:
                                # Build conversation history
                                conversation_history = [
                                    msg for msg in st.session_state[chat_key] 
                                    if msg["role"] in ["user", "assistant"]
                                ]
                                
                                # Prepare headers text for chat
                                headers_text_chat = f"""From: {selected_email.get('from', '')}
To: {selected_email.get('to', '')}
Subject: {selected_email.get('subject', '')}
Date: {selected_email.get('date', '')}
Reply-To: {selected_email.get('reply_to', '')}
Return-Path: {selected_email.get('return_path', '')}

=== AUTHENTICATION RESULTS ===
SPF: {selected_email.get('spf', 'n/a')}
DKIM: {selected_email.get('dkim', 'n/a')}
DMARC: {selected_email.get('dmarc', 'n/a')}

=== ANALYSIS SCORES ===
Total Score: {selected_email.get('total_score', 0)}/100
AI Score: {selected_email.get('gpt_score', 0)}/60
BERT Score: {selected_email.get('bert_score', 0)}/25
Domain Score: {selected_email.get('domain_score', 0)}/15

=== SENDER REPUTATION ===
Sender Domain: {selected_email.get('sender_domain', 'n/a')}
Domain Analysis: {json.dumps(selected_email.get('domain_result', {})) if selected_email.get('domain_result') else 'n/a'}
"""
                                
                                # Create initial analysis summary
                                initial_analysis_dict = {
                                    "verdict": selected_email.get('verdict', 'Unknown'),
                                    "confidence": "Medium",
                                    "recommendation": selected_email.get('gpt_reason', ''),
                                    "critical_findings": [
                                        selected_email.get('gpt_verdict', ''),
                                        f"BERT: {selected_email.get('bert_label', '')} ({selected_email.get('bert_confidence', 0):.2%})",
                                        f"Domain: {selected_email.get('domain_score', 0)}/15"
                                    ],
                                    "authentication_status": {
                                        "spf": selected_email.get('spf', 'n/a'),
                                        "dkim": selected_email.get('dkim', 'n/a'),
                                        "dmarc": selected_email.get('dmarc', 'n/a')
                                    },
                                    "scores": {
                                        "total": selected_email.get('total_score', 0),
                                        "ai": selected_email.get('gpt_score', 0),
                                        "bert": selected_email.get('bert_score', 0),
                                        "domain": selected_email.get('domain_score', 0)
                                    }
                                }
                                
                                if USE_GROQ_AGENT:
                                    # Use Groq chat
                                    debug_log("💬 Gmail chat using Groq")
                                    response = groq_agent.chat(
                                        headers=headers_text_chat,
                                        body="",  # Empty body for Gmail
                                        question=user_input,
                                        initial_analysis=initial_analysis_dict,
                                        conversation_history=conversation_history[:-1]
                                    )
                                else:
                                    # Use OpenAI chat
                                    debug_log("💬 Gmail chat using OpenAI")
                                    initial_analysis_json = json.dumps(initial_analysis_dict)
                                    response, _ = chat_with_llm(
                                        headers=headers_text_chat,
                                        body="",  # Empty body for Gmail
                                        user_question=user_input,
                                        initial_analysis=initial_analysis_json,
                                        conversation_history=conversation_history[:-1],
                                        model_name=MODEL_NAME
                                    )
                                
                                st.session_state[chat_key].append({"role": "assistant", "content": response})
                                
                            except Exception as e:
                                error_msg = f"Sorry, I encountered an error: {str(e)}"
                                st.session_state[chat_key].append({
                                    "role": "assistant", 
                                    "content": error_msg
                                })
                        
                        try:
                            st.rerun()
                        except AttributeError:
                            st.experimental_rerun()

                # Export option
                csv = df.to_csv(index=False)
                st.download_button(
                    label="📊 Export to CSV",
                    data=csv,
                    file_name=f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

# ============================================================================
# PAGE: SETTINGS
# ============================================================================

elif page == "⚙️ Settings":
    st.markdown("""
        <div style='text-align: center; margin-top: 50px;'>
            <h1 style='color: white;'>⚙️ System Settings</h1>
        </div>
    """, unsafe_allow_html=True)

    st.subheader("🤖 AI Provider Configuration")
    
    current_provider = "Groq (Llama)" if USE_GROQ_AGENT else "OpenAI (GPT-4o-mini)"
    st.info(f"**Current Provider:** {current_provider}")
    
    st.markdown("""
    **To change the AI provider:**
    
    1. Open this file (`app_complete.py`)
    2. Find line ~21: `USE_GROQ_AGENT = True`
    3. Change to:
       - `USE_GROQ_AGENT = True` → Use Groq (Free, Llama models)
       - `USE_GROQ_AGENT = False` → Use OpenAI (GPT-4o-mini)
    4. Restart the Streamlit app
    """)
    
    st.markdown("---")
    st.subheader("📊 System Information")
    st.write(f"**Model Name:** {MODEL_NAME}")
    st.write(f"**Backend URL:** {BACKEND_URL}")
    st.write(f"**Logging:** phishing_detection.log")

st.markdown("---")
st.markdown("<p style='text-align: center; color: gray;'>Phishing Email Detection System v2.0</p>", unsafe_allow_html=True)