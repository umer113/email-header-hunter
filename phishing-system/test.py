
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

from config import OPENAI_API_KEY, VIRUS_TOTAL_API
from agents.LLM_agent import classify_with_llm, chat_with_llm
from agents.ai_agent import PhishingDetector
from models.distilBert import distilBert
from checker.domain_checker import check_sender_domain, extract_sender_domain
from checker.url_check import extract_urls_from_body, scan_and_check_url
from agents.extractor_agent import extract_headers_and_text, extract_email_fields

st.set_page_config(
    page_title="Email Header Hunter",
    layout="wide",
    initial_sidebar_state="expanded"
)


USE_GROQ_AGENT = True  
MODEL_NAME = "gpt-4o-mini"
BACKEND_URL = "http://localhost:8000"

logging.basicConfig(
    filename='phishing_detection.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

groq_agent = PhishingDetector()

def debug_log(message: str):
    print(f"[DEBUG] {message}", file=sys.stderr, flush=True)
    logging.info(message)


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
if "auto_sync_enabled" not in st.session_state:
    st.session_state.auto_sync_enabled = False
if "last_sync_time" not in st.session_state:
    st.session_state.last_sync_time = None
if "sync_interval" not in st.session_state:
    st.session_state.sync_interval = 20  
if "analysis_stats" not in st.session_state:
    st.session_state.analysis_stats = {
        "total_analyzed": 0,
        "legit_count": 0,
        "suspicious_count": 0,
        "phishing_count": 0
    }
if "show_auto_sync_dashboard" not in st.session_state:
    st.session_state.show_auto_sync_dashboard = False

def analyze_email_with_ai(headers_text, body_text, query="Is this email phishing or legitimate?"):
    """
    Analyze email using either Groq or OpenAI based on global setting
    Returns: (result_json_string, usage_dict)
    """
    if USE_GROQ_AGENT:
        logging.critical("🔥 GUARDIAN AI (GROQ) SELECTED")
        
        groq_result = groq_agent.analyze(
            headers=headers_text,
            # body=body_text,
            query=query
        )
        
        result_json = json.dumps(groq_result)
        usage = {"total_tokens": 0, "model": "guardian-ai-groq"}
        
        logging.critical(f"✅ Guardian AI result: {result_json[:200]}")
            
        return result_json, usage
    else:
        with st.spinner("🔵 OpenAI GPT-4o is analyzing email security..."):
            logging.critical("🔄 OPENAI SELECTED")
            
            result, usage = classify_with_llm(
                headers_text,
                body_text,
                user_question=query,
                model_name=MODEL_NAME
            )
            
            logging.critical(f"✅ result: {result[:200] if isinstance(result, str) else str(result)[:200]}")
            
        st.success("✅ analysis complete")
        return result, usage

def calculate_scores(gpt_result, headers_text, body_text, sender_domain=None, url_results=None):
    """
    scoring (Total = 100)
    Auth (SPF/DKIM/DMARC) = 40
    DistilBERT            = 30
    Domain reputation     = 20
    URL safety            = 10
    """

    auth_results = (headers_text or "").lower()

    def _is_pass(key: str) -> bool:
        return (f"{key}=pass" in auth_results) or (f"{key}: pass" in auth_results)

    spf_pass = _is_pass("spf")
    dkim_pass = _is_pass("dkim")
    dmarc_pass = _is_pass("dmarc")

    pass_count = sum([spf_pass, dkim_pass, dmarc_pass])

    if pass_count == 3:
        auth_score = 40
    elif pass_count == 2:
        auth_score = 25
    elif pass_count == 1:
        auth_score = 15
    else:
        auth_score = 5


    vote_label, vote_confidence = distilBert(headers_text, body_text)
    vote_confidence = float(vote_confidence or 0.0)

    if "phishing" in (vote_label or "").lower():
        bert_score = int(30 * (1 - vote_confidence))
    else:
        bert_score = int(30 * vote_confidence)


    domain_score = 10  
    domain_result = None

    if sender_domain:
        try:
            domain_result = check_sender_domain(sender_domain, VIRUS_TOTAL_API)
            malicious = 0
            suspicious = 0
            if isinstance(domain_result, dict):
                malicious = int(domain_result.get("malicious", 0) or 0)
                suspicious = int(domain_result.get("suspicious", 0) or 0)

            if malicious > 0:
                domain_score = 0
            elif suspicious > 0:
                domain_score = 10
            else:
                domain_score = 20

        except Exception as e:
            logging.error(f"Domain check error: {e}")
            domain_score = 10


    url_score = 10  
    if url_results:
        try:
            any_malicious = False
            any_suspicious = False

            for _, res in url_results:
                if isinstance(res, dict) and "error" not in res:
                    m = int(res.get("malicious", 0) or 0)
                    s = int(res.get("suspicious", 0) or 0)
                    if m > 0:
                        any_malicious = True
                        break
                    if s > 0:
                        any_suspicious = True

            if any_malicious:
                url_score = 0
            elif any_suspicious:
                url_score = 5
            else:
                url_score = 10
        except Exception as e:
            logging.error(f"URL score error: {e}")
            url_score = 5

    total_score = auth_score + bert_score + domain_score + url_score

    try:
        gpt_json = gpt_result if isinstance(gpt_result, dict) else json.loads(gpt_result)
        gpt_verdict = gpt_json.get("verdict", "")
        gpt_reason = gpt_json.get("reason", "") or gpt_json.get("recommendation", "")
    except Exception:
        gpt_verdict = ""
        gpt_reason = ""

    gpt_score = 0
    v = (gpt_verdict or "").lower()

    if "legit" in v or "legitimate" in v:
        gpt_score = 40
    elif "suspicious" in v:
        gpt_score = 20
    elif "phish" in v:
        gpt_score = 0
    else:
        gpt_score = 10  


    return (
        total_score,
        gpt_score,    
        gpt_verdict,
        gpt_reason,
        bert_score,
        vote_label,
        vote_confidence,
        domain_score,
        domain_result,
        url_score
    )


def get_final_verdict(total_score):
    if total_score >= 75:
        return "Legit", "green"
    elif total_score >= 40:
        return "Suspicious", "orange"
    else:
        return "Phishing", "red"




def fetch_and_analyze_new_emails():
    """Fetch and analyze new emails from Gmail (incremental)"""
    try:
        last_internal_date = st.session_state.get("last_analyzed_internal_date", None)
        
        print("\n" + "="*80)
        print("🔍 AUTO-SYNC DEBUG START")
        print("="*80)
        print(f"📊 Last analyzed internal_date: {last_internal_date}")
        
      
        if last_internal_date is None:
            print("🆕 FIRST SYNC - Getting latest 2 emails")
            response = requests.get(
                f"{BACKEND_URL}/gmail/emails", 
                params={"max_results": 1}
            )
        else:
            print(f"🔄 INCREMENTAL SYNC - Getting emails after: {last_internal_date}")
            response = requests.get(
                f"{BACKEND_URL}/gmail/emails/incremental",
                params={"after_internal_date": str(last_internal_date)}
            )
        
        if response.status_code != 200:
            print("❌ Failed to fetch emails from backend")
            return False, "Failed to fetch emails"
        
        data = response.json()
        emails = data.get("emails", [])
        
        print(f"\n📥 FETCHED {len(emails)} emails from Gmail")
        
        if not emails:
            print("✅ No new emails found")
            print("="*80 + "\n")
            return True, "No new emails"
        
      
        print("\n📧 FETCHED EMAILS:")
        for idx, email in enumerate(emails):
            print(f"  [{idx+1}] ID: {email.get('id')[:20]}... | Internal Date: {email.get('internal_date')} | Subject: {email.get('subject', 'No Subject')[:50]}")
        
        emails.sort(key=lambda x: int(x.get("internal_date", 0)))
        
        print(f"\n🔄 SORTED {len(emails)} emails by internal_date (oldest first)")
        
        analyzed_count = 0
        skipped_count = 0
        latest_internal_date = last_internal_date
        
        print("\n🔍 CHECKING EACH EMAIL:")
        print("-" * 80)
        
        for idx, email_data in enumerate(emails):
            email_id = email_data.get("id")
            email_internal_date = email_data.get("internal_date")
            email_subject = email_data.get("subject", "No Subject")[:50]
            
            print(f"\n[{idx+1}/{len(emails)}] Processing: {email_subject}")
            print(f"    Email ID: {email_id[:20]}...")
            print(f"    Internal Date: {email_internal_date}")
            
            check_response = requests.get(
                f"{BACKEND_URL}/analysis/check_analyzed",
                params={"email_id": email_id}
            )
            
            if check_response.status_code == 200:
                check_data = check_response.json()
                if check_data.get("analyzed"):
                    print(f"    ⏭️  SKIPPED - Already analyzed")
                    skipped_count += 1
                    if email_internal_date and int(email_internal_date) > int(latest_internal_date or 0):
                        latest_internal_date = email_internal_date
                        print(f"    📌 Updated latest_internal_date to: {latest_internal_date}")
                    continue 
            
            print(f"    🆕 NEW EMAIL - Starting analysis...")
            

            headers_text = f"""From: {email_data.get('from', '')}
To: {email_data.get('to', '')}
Subject: {email_data.get('subject', '')}
Date: {email_data.get('date', '')}
Reply-To: {email_data.get('reply_to', '')}
Return-Path: {email_data.get('return_path', '')}
SPF: {email_data.get('spf', 'unknown')}
DKIM: {email_data.get('dkim', 'unknown')}
DMARC: {email_data.get('dmarc', 'unknown')}
"""
            
            body_text = ""
            sender_domain = None
            if email_data.get('from'):
                match = re.search(r'@([a-zA-Z0-9.-]+)', email_data['from'])
                if match:
                    sender_domain = match.group(1)
            
            print(f"    🤖 Running AI analysis...")
            gpt_result, _ = analyze_email_with_ai(
                headers_text,
                # body_text,
                "Based on these email headers, is this email phishing or legitimate?"
            )
            
            print(f"    📊 Calculating scores...")
            (total_score, gpt_score, gpt_verdict, gpt_reason, bert_score,
                vote_label, vote_confidence, domain_score, domain_result, url_score) = calculate_scores(
                    gpt_result, headers_text, body_text, sender_domain, url_results=None
                )


            
            final_verdict, _ = get_final_verdict(total_score)
            
            print(f"    ✅ Analysis complete: {final_verdict} (Score: {total_score}/100)")
            
           
            save_data = {
                "user_id": "default_user",
                "email_id": email_id,
                "verdict": final_verdict,
                "total_score": total_score,
                "from_address": email_data.get('from', ''),
                "subject": email_data.get('subject', ''),
                "date": email_data.get('date', ''),
                "gpt_verdict": gpt_verdict,
                "gpt_score": gpt_score,
                "bert_score": bert_score,
                "domain_score": domain_score
            }
            
            print(f"    💾 Saving to backend...")
            save_response = requests.post(f"{BACKEND_URL}/analysis/save", json=save_data)
            
            if save_response.status_code == 200:
                print(f"    ✅ Saved successfully - NOW IN ARRAY (won't analyze again)")
            else:
                print(f"    ❌ Save failed")
            
            analyzed_count += 1
            
            if email_internal_date and int(email_internal_date) > int(latest_internal_date or 0):
                latest_internal_date = email_internal_date
                print(f"    📌 Updated latest_internal_date to: {latest_internal_date}")
            
            time.sleep(1)  
        
        print("\n" + "="*80)
        print("📊 SYNC SUMMARY")
        print("="*80)
        print(f"Total fetched: {len(emails)}")
        print(f"Already analyzed (skipped): {skipped_count}")
        print(f"Newly analyzed: {analyzed_count}")
        print(f"Final latest_internal_date: {latest_internal_date}")
        
        if latest_internal_date:
            st.session_state.last_analyzed_internal_date = latest_internal_date
            print(f"✅ Session state updated with: {latest_internal_date}")
        
        print("\n🔍 NEXT SYNC WILL FETCH EMAILS AFTER: {latest_internal_date}")
        print("="*80 + "\n")
        
        stats_response = requests.get(f"{BACKEND_URL}/analysis/stats")
        if stats_response.status_code == 200:
            st.session_state.analysis_stats = stats_response.json()
        
        return True, f"Analyzed {analyzed_count} new emails (Skipped {skipped_count} already analyzed)"
        
    except Exception as e:
        print(f"\n❌ ERROR in auto-sync: {str(e)}")
        print("="*80 + "\n")
        logging.error(f"Auto-sync error: {e}")
        return False, str(e)

def should_sync():
    if not st.session_state.auto_sync_enabled:
        return False
    
    if st.session_state.last_sync_time is None:
        return True
    
    elapsed = (datetime.now() - st.session_state.last_sync_time).total_seconds()
    return elapsed >= st.session_state.sync_interval

with st.sidebar:
    st.markdown("""
        <div style='text-align: center; margin-bottom: 30px;'>
            <h2 style='color: #1f77b4;'>🛡️ Email Header Hunter</h2>
        </div>
    """, unsafe_allow_html=True)
    
    page = st.selectbox(
        "Select Analysis Mode",
        ["📧 Upload Email", "📬 Gmail Dashboard"],
        index=0
    )
    
    st.markdown("---")
    
    ai_provider = "🤖 Eagle AI" if USE_GROQ_AGENT else "🔵 OpenAI (GPT-4o-mini)"
    st.info(f"**Agent:** {ai_provider}")
    
    # st.markdown("---")
    # st.markdown("""
    #     <div style='padding: 15px; background-color: rgba(30, 144, 255, 0.1); border-radius: 10px;'>
    #         <h4 style='color: #1f77b4; margin-bottom: 10px;'>🔍 Detection Features</h4>
    #         <ul style='font-size: 12px; color: #666;'>
    #             <li>AI-Powered Analysis</li>
    #             <li>DistilBERT Classification</li>
    #             <li>Domain Reputation Check</li>
    #             <li>URL Safety Scanning</li>
    #             <li>Interactive Chat Agent</li>
    #         </ul>
    #     </div>
    # """, unsafe_allow_html=True)

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

    uploaded_file = st.file_uploader("Upload email file", type=None, label_visibility="collapsed")
    
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

                if st.session_state.analysis_cache is None:
                    gpt_result, gpt_usage = analyze_email_with_ai(
                        headers,
                        body,
                        "Is this email phishing or legitimate?"
                    )
                    st.session_state.analysis_cache = (gpt_result, gpt_usage)
                else:
                    gpt_result, gpt_usage = st.session_state.analysis_cache

                url_results = []
                for url in urls[:5]:
                    try:
                        url_results.append((url, scan_and_check_url(url, VIRUS_TOTAL_API)))
                    except Exception as e:
                        url_results.append((url, {"error": str(e)}))

                (total_score, gpt_score, gpt_verdict, gpt_reason, bert_score,
                    vote_label, vote_confidence, domain_score, domain_result, url_score) = calculate_scores(
                        gpt_result, headers_text, body, sender_domain, url_results=url_results
                    )

                print(f"✅ Scores calculated: {total_score}, {gpt_score}, {bert_score}, {domain_score}, {url_score}")

                print(f"urls found: ${url_results}")

                malicious_count = sum(
                    result.get("malicious", 0) > 0
                    for _, result in url_results
                    if isinstance(result, dict)
                )

            final_verdict, verdict_color = get_final_verdict(total_score)
            
            st.markdown("---")
            st.subheader("Final Verdict")
            st.markdown(f"### {final_verdict}  \n**Total Score:** `{total_score}/100`")

            show_details = st.toggle("🔎 View Full Analysis", value=False, key="analysis_toggle")

            if show_details:
                st.subheader("Eagle AI Analysis")
                st.markdown(f"**Verdict:** {gpt_verdict}")
                st.markdown(f"**Reasoning:** {gpt_reason}")
                st.markdown(f"**Score:** {gpt_score}/40")
                st.subheader("DistilBERT Classification")
                st.markdown(f"**{vote_label}** (Confidence: {vote_confidence:.2%})")
                st.markdown(f"**Score:** {bert_score}/30")

                st.subheader("Sender Domain Reputation")
                if sender_domain:
                    st.markdown(f"**Sender Domain:** `{sender_domain}`")
                    st.markdown(f"**Domain Score:** {domain_score}/20")
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
                    st.markdown(f"- AI Agent → **{gpt_score}/40**")
                    st.markdown(f"- DistilBERT → **{bert_score}/30**")
                    st.markdown(f"- Domain Reputation → **{domain_score}/20**")
                    st.markdown(f"- URL Safety → **{url_score}/10**")


            st.success("✅ Email analyzed successfully.")

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
                            debug_log("💬 Using Groq chat")
                            
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
                                # body=body,
                                question=user_input,
                                initial_analysis=initial_analysis_dict,
                                conversation_history=st.session_state.chat_history[:-1]
                            )
                            usage = {"total_tokens": 0, "model": "groq"}
                        else:
                            debug_log("💬 Using OpenAI chat")
                            response_text, usage = chat_with_llm(
                                headers=headers,
                                # body=body,
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

        try:
            query_params = st.query_params
            if query_params.get("authenticated") == "true":
                st.session_state.gmail_authenticated = True
                st.rerun()
        except AttributeError:
            query_params = st.experimental_get_query_params()
            if "authenticated" in query_params and query_params["authenticated"][0] == "true":
                st.session_state.gmail_authenticated = True
                try:
                    st.rerun()
                except AttributeError:
                    st.experimental_rerun()

    else:
        try:
            stats_response = requests.get(f"{BACKEND_URL}/analysis/stats")
            if stats_response.status_code == 200:
                st.session_state.analysis_stats = stats_response.json()
        except:
            pass
        
        col_toggle1, col_toggle2 = st.columns([3, 1])
        with col_toggle1:
            st.markdown("### 🤖 Auto-Sync Dashboard")
        with col_toggle2:
            show_dashboard = st.toggle("Show/Hide", value=st.session_state.show_auto_sync_dashboard, key="dashboard_toggle")
            st.session_state.show_auto_sync_dashboard = show_dashboard
        
        if st.session_state.show_auto_sync_dashboard:
            col1, col2, col3, col4, col5 = st.columns(5)
            
            stats = st.session_state.analysis_stats
            
            with col1:
                st.markdown("""
                    <div style='padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; text-align: center;'>
                        <h2 style='color: white; margin: 0;'>{}</h2>
                        <p style='color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 14px;'>Total Analyzed</p>
                    </div>
                """.format(stats["total_analyzed"]), unsafe_allow_html=True)
            
            with col2:
                st.markdown("""
                    <div style='padding: 20px; background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); border-radius: 10px; text-align: center;'>
                        <h2 style='color: white; margin: 0;'>{}</h2>
                        <p style='color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 14px;'>✅ Legit</p>
                    </div>
                """.format(stats["legit_count"]), unsafe_allow_html=True)
            
            with col3:
                st.markdown("""
                    <div style='padding: 20px; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); border-radius: 10px; text-align: center;'>
                        <h2 style='color: white; margin: 0;'>{}</h2>
                        <p style='color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 14px;'>⚠️ Suspicious</p>
                    </div>
                """.format(stats["suspicious_count"]), unsafe_allow_html=True)
            
            with col4:
                st.markdown("""
                    <div style='padding: 20px; background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); border-radius: 10px; text-align: center;'>
                        <h2 style='color: white; margin: 0;'>{}</h2>
                        <p style='color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 14px;'>🚨 Phishing</p>
                    </div>
                """.format(stats["phishing_count"]), unsafe_allow_html=True)
            
            with col5:
                if stats["total_analyzed"] > 0:
                    safety_rate = round((stats["legit_count"] / stats["total_analyzed"]) * 100, 1)
                else:
                    safety_rate = 0
                
                st.markdown("""
                    <div style='padding: 20px; background: linear-gradient(135deg, #30cfd0 0%, #330867 100%); border-radius: 10px; text-align: center;'>
                        <h2 style='color: white; margin: 0;'>{}%</h2>
                        <p style='color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 14px;'>Safety Rate</p>
                    </div>
                """.format(safety_rate), unsafe_allow_html=True)
            
            st.markdown("---")
            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
            
            with col1:
                sync_status = "🟢 Active" if st.session_state.auto_sync_enabled else "🔴 Inactive"
                st.markdown(f"**Auto-Sync Status: {sync_status}**")
                
                if st.session_state.last_sync_time:
                    elapsed = (datetime.now() - st.session_state.last_sync_time).total_seconds()
                    next_sync = max(0, st.session_state.sync_interval - elapsed)
                    st.caption(f"Last sync: {int(elapsed)}s ago | Next sync in: {int(next_sync)}s")
            
            with col2:
                if st.button("🔄 Start Auto-Sync" if not st.session_state.auto_sync_enabled else "⏸️ Stop Auto-Sync", 
                            type="primary", use_container_width=True, key="toggle_auto_sync"):
                    st.session_state.auto_sync_enabled = not st.session_state.auto_sync_enabled
                    
                    if st.session_state.auto_sync_enabled:
                        st.session_state.last_analyzed_internal_date = None
                        st.success("✅ Auto-sync enabled! Fetching latest emails...")
                    else:
                        st.info("⏸️ Auto-sync paused")
                    try:
                        st.rerun()
                    except AttributeError:
                        st.experimental_rerun()
            
            with col3:
                if st.button("🔍 Sync Now", type="secondary", use_container_width=True, key="manual_sync_button"):
                    with st.spinner("Syncing emails..."):
                        success, message = fetch_and_analyze_new_emails()
                        st.session_state.last_sync_time = datetime.now()
                        
                        if success:
                            st.success(f"✅ {message}")
                        else:
                            st.error(f"❌ {message}")
                        
                        try:
                            st.rerun()
                        except AttributeError:
                            st.experimental_rerun()
            
            with col4:
                if st.button("🗑️ Clear History", type="secondary", use_container_width=True, key="clear_auto_history"):
                    try:
                        requests.delete(f"{BACKEND_URL}/analysis/clear")
                        st.session_state.analysis_stats = {
                            "total_analyzed": 0,
                            "legit_count": 0,
                            "suspicious_count": 0,
                            "phishing_count": 0
                        }
                        st.success("✅ History cleared!")
                        try:
                            st.rerun()
                        except AttributeError:
                            st.experimental_rerun()
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
            
            new_interval = st.slider(
                "Sync Interval (seconds)",
                min_value=20,
                max_value=60,
                value=st.session_state.sync_interval,
                step=10,
                help="How often to check for new emails",
                key="sync_interval_slider"
            )
            if new_interval != st.session_state.sync_interval:
                st.session_state.sync_interval = new_interval
            if st.session_state.auto_sync_enabled:
                if should_sync():
                    with st.spinner("🔄 Checking for new emails..."):
                        success, message = fetch_and_analyze_new_emails()
                        st.session_state.last_sync_time = datetime.now()
                        
                        if success:
                            if "Analyzed" in message:
                                analyzed_num = int(message.split()[1]) if message.split()[1].isdigit() else 0
                                if analyzed_num > 0:
                                    st.success(f"✅ {message}")
                                    time.sleep(1)
                                    try:
                                        st.rerun()
                                    except AttributeError:
                                        st.experimental_rerun()
                                else:
                                    st.info("No new emails to analyze")
                        else:
                            st.warning(f"⚠️ {message}")
                
                time.sleep(5)
                try:
                    st.rerun()
                except AttributeError:
                    st.experimental_rerun()
            
            st.markdown("---")
            st.subheader("📜 Auto-Sync Analysis History")
            
            try:
                history_response = requests.get(f"{BACKEND_URL}/analysis/history", params={"limit": 50})
                if history_response.status_code == 200:
                    history_data = history_response.json()
                    history = history_data.get("history", [])
                    
                    if history:
                        display_data = []
                        for item in history:
                            display_data.append({
                                "Date": item.get("date", "")[:16],
                                "From": item.get("from_address", "")[:50],
                                "Subject": item.get("subject", "")[:60],
                                "Verdict": item.get("verdict", ""),
                                "Score": f"{item.get('total_score', 0)}/100",
                            })
                        
                        df = pd.DataFrame(display_data)
                        st.dataframe(df, use_container_width=True, height=300)
                        
                        # Export option
                        csv = df.to_csv(index=False)
                        st.download_button(
                            label="📊 Export Auto-Sync History to CSV",
                            data=csv,
                            file_name=f"auto_sync_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv",
                            key="export_auto_sync_csv"
                        )
                    else:
                        st.info("No auto-sync history yet. Start auto-sync to begin analyzing emails automatically.")
            except Exception as e:
                st.error(f"Error loading history: {str(e)}")
        
        st.markdown("---")
        

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
                try:
                    requests.post(f"{BACKEND_URL}/auth/logout", timeout=10)
                except Exception as e:
                    st.warning(f"Backend logout error: {e}")

                st.session_state.gmail_authenticated = False
                st.session_state.gmail_emails = []
                st.session_state.analyzed_emails = []
                st.session_state.auto_sync_enabled = False
                st.session_state.last_analyzed_internal_date = None
                st.session_state.last_sync_time = None
                st.session_state.show_auto_sync_dashboard = False

                try:
                    st.query_params.clear()
                except Exception:
                    pass

                st.success("✅ Gmail account disconnected!")
                st.rerun()


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

                            gpt_result, gpt_usage = analyze_email_with_ai(
                                headers_text,
                                body_text,
                                "Based on these email headers, is this email phishing or legitimate?"
                            )

                            (total_score, gpt_score, gpt_verdict, gpt_reason, bert_score,
                            vote_label, vote_confidence, domain_score, domain_result, url_score) = calculate_scores(
                                gpt_result, headers_text, body_text, sender_domain, url_results=None
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

                        time.sleep(1)  

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

            with st.expander("📋 View Raw Email Headers", expanded=False):
                if st.session_state.gmail_emails:
                    df = pd.DataFrame(st.session_state.gmail_emails)
                    st.dataframe(df, use_container_width=True)

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

                st.markdown("### 🔍 Detailed Email Analysis")
                selected_email_index = st.selectbox(
                    "Select email for detailed analysis:",
                    range(len(st.session_state.analyzed_emails)),
                    format_func=lambda x: f"{st.session_state.analyzed_emails[x].get('subject', 'No Subject')[:80]}..."
                )

                if selected_email_index is not None:
                    selected_email = st.session_state.analyzed_emails[selected_email_index]
                    
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

                    tab1, tab2, tab3 = st.tabs(["🤖 AI Analysis", "🔒 Authentication", "🌐 Domain Check"])

                    with tab1:
                        st.subheader("AI Security Analysis")
                        st.markdown(f"**Verdict:** {selected_email.get('gpt_verdict', 'N/A')}")
                        st.markdown(f"**Reasoning:** {selected_email.get('gpt_reason', 'N/A')}")
                        st.markdown(f"**Score:** {selected_email.get('gpt_score', 0)}/40")
                        
                        st.subheader("DistilBERT Classification")
                        st.markdown(f"**Label:** {selected_email.get('bert_label', 'N/A')}")
                        st.markdown(f"**Confidence:** {selected_email.get('bert_confidence', 0):.2%}")
                        st.markdown(f"**Score:** {selected_email.get('bert_score', 0)}/30")
                        
                        st.subheader("📊 Grading Breakdown")
                        st.markdown(f"- **AI Analysis:** `{selected_email.get('gpt_verdict', 'N/A')}` → **{selected_email.get('gpt_score', 0)}/40**")
                        st.markdown(f"- **DistilBERT:** `{selected_email.get('bert_label', 'N/A')}` (Confidence: {selected_email.get('bert_confidence', 0):.2%}) → **{selected_email.get('bert_score', 0)}/30**")
                        st.markdown(f"- **Domain Reputation:** → **{selected_email.get('domain_score', 0)}/20**")


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

                    st.markdown("---")
                    st.subheader("💬 Chat with Eagle AI Agent")
                    
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
                                conversation_history = [
                                    msg for msg in st.session_state[chat_key] 
                                    if msg["role"] in ["user", "assistant"]
                                ]
                                
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
                                    debug_log("💬 Gmail chat using Groq")
                                    response = groq_agent.chat(
                                        headers=headers_text_chat,
                                        # body="",  
                                        question=user_input,
                                        initial_analysis=initial_analysis_dict,
                                        conversation_history=conversation_history[:-1]
                                    )
                                else:
                                    debug_log("💬 Gmail chat using OpenAI")
                                    initial_analysis_json = json.dumps(initial_analysis_dict)
                                    response, _ = chat_with_llm(
                                        headers=headers_text_chat,
                                        # body="",  
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

                csv = df.to_csv(index=False)
                st.download_button(
                    label="📊 Export to CSV",
                    data=csv,
                    file_name=f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )



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
st.markdown("<p style='text-align: center; color: gray;'>Email Header Hunter v2.0</p>", unsafe_allow_html=True)