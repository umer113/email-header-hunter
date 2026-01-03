from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import os
import json
from typing import Optional
import uvicorn

# NEW IMPORTS
from datetime import datetime, timedelta
import threading
from pathlib import Path
from google.auth.transport.requests import Request

# load .env
from dotenv import load_dotenv
load_dotenv()

# ---- SCOPES (identity + headers-only) ----
SCOPES = [
    "openid", 
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.metadata",  # headers only (no body)
]

# distilbert

# openid is used for login
# user.info.profile --> to extract user's email

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
STREAMLIT_URL = os.getenv("STREAMLIT_URL", "http://localhost:8501")

# ============================================================================
# JSON FILES FOR STORAGE - NEW
# ============================================================================
TOKENS_FILE = Path("user_tokens.json")
ANALYSIS_FILE = Path("email_analysis.json")

def load_json_file(filepath: Path):
    """Load JSON file or return empty dict"""
    if filepath.exists():
        try:
            with open(filepath, 'r') as f:
                content = f.read().strip()
                if not content:  # Empty file
                    return {}
                return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"⚠️ Warning: Corrupted JSON file {filepath}, recreating...")
            import shutil
            shutil.move(str(filepath), str(filepath) + ".backup")
            return {}
        except Exception as e:
            print(f"❌ Error reading {filepath}: {e}")
            return {}
    return {}

def save_json_file(filepath: Path, data: dict):
    """Save data to JSON file"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

# Initialize files if they don't exist
if not TOKENS_FILE.exists():
    save_json_file(TOKENS_FILE, {})
if not ANALYSIS_FILE.exists():
    save_json_file(ANALYSIS_FILE, {
        "users": {},
        "system_start_time": None  # Will be set when user enables auto-sync
    })

def save_credentials_to_json(user_id: str, creds):
    tokens_data = load_json_file(TOKENS_FILE)
    
    tokens_data[user_id] = {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
        "created_at": datetime.now().isoformat(),
        "last_sync": datetime.now().isoformat()
    }
    
    save_json_file(TOKENS_FILE, tokens_data)

def load_credentials_from_json(user_id: str):
    """Load credentials from JSON file"""
    from google.oauth2.credentials import Credentials
    
    tokens_data = load_json_file(TOKENS_FILE)
    
    if user_id not in tokens_data:
        return None
    
    user_data = tokens_data[user_id]
    
    creds = Credentials(
        token=user_data["access_token"],
        refresh_token=user_data["refresh_token"],
        token_uri=user_data["token_uri"],
        client_id=user_data["client_id"],
        client_secret=user_data["client_secret"],
        scopes=user_data["scopes"]
    )
    
    if user_data.get("expiry"):
        creds.expiry = datetime.fromisoformat(user_data["expiry"])
    
    return creds

def refresh_token_if_needed(user_id: str):
    """Refresh token if expired"""
    creds = user_credentials.get(user_id)
    if not creds:
        creds = load_credentials_from_json(user_id)
        if creds:
            user_credentials[user_id] = creds
    
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        save_credentials_to_json(user_id, creds)
        user_credentials[user_id] = creds
    
    return creds

def update_last_sync(user_id: str):
    """Update last sync timestamp"""
    tokens_data = load_json_file(TOKENS_FILE)
    if user_id in tokens_data:
        tokens_data[user_id]["last_sync"] = datetime.now().isoformat()
        save_json_file(TOKENS_FILE, tokens_data)

# ============================================================================

print(f"GOOGLE_REDIRECT_URI: {GOOGLE_REDIRECT_URI}")
if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
    raise RuntimeError("Missing env vars. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET in .env")

def flow_obj() -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI],
            }
        },
        scopes=SCOPES,
    )

app = FastAPI(title="Gmail OAuth Backend for Phishing Detection")

# Store credentials temporarily (in production, use proper session management)
user_credentials = {}

@app.get("/")
def home():
    return {"ok": True, "message": "Gmail OAuth Backend Running", "auth_url": "/auth/google"}



@app.get("/gmail/emails/incremental")
def get_gmail_emails_incremental(user_id: str = "default_user", after_internal_date: str = None):
    """Get emails after a specific internal date (for real-time sync)"""
    creds = refresh_token_if_needed(user_id)
    
    if not creds:
        raise HTTPException(400, "User not authenticated. Please authenticate first.")
    
    update_last_sync(user_id)
    
    try:
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)

        # Get all recent messages (last 50)
        query_params = {
            "userId": "me",
            "labelIds": ["INBOX"],
            "maxResults": 10
        }
        
        resp = service.users().messages().list(**query_params).execute()
        message_ids = [m["id"] for m in resp.get("messages", [])]

        if not message_ids:
            return JSONResponse({"count": 0, "emails": []})

        # Batch fetch metadata
        metas: list[dict] = []

        def _callback(request_id, response, exception):
            if response:
                metas.append(response)
            if exception:
                print(f"Batch request error: {exception}")

        batch = service.new_batch_http_request(callback=_callback)
        for mid in message_ids:
            batch.add(
                service.users().messages().get(
                    userId="me",
                    id=mid,
                    format="metadata",
                    metadataHeaders=[
                        "From", "To", "Subject", "Date", "Message-Id",
                        "Reply-To", "Return-Path", "Received",
                        "Authentication-Results", "List-Id", "X-Spam-Score",
                        "X-Spam-Status", "Received-SPF"
                    ],
                )
            )
        batch.execute()

        # Extract email data
        def extract_email_data(message: dict) -> dict:
            headers = {h["name"]: h["value"] for h in message.get("payload", {}).get("headers", [])}
            
            auth_results = headers.get("Authentication-Results", "") or ""
            
            def get_header(name): 
                return headers.get(name, "")
            
            def extract_auth_status(auth_string, protocol):
                if f"{protocol}=pass" in auth_string.lower():
                    return "pass"
                elif f"{protocol}=fail" in auth_string.lower():
                    return "fail"
                elif f"{protocol}=neutral" in auth_string.lower():
                    return "neutral"
                elif f"{protocol}=softfail" in auth_string.lower():
                    return "softfail"
                else:
                    return "n/a"
            
            return {
                "id": message.get("id"),
                "thread_id": message.get("threadId"),
                "date": get_header("Date"),
                "internal_date": message.get("internalDate"),
                "from": get_header("From"),
                "to": get_header("To"),
                "subject": get_header("Subject"),
                "reply_to": get_header("Reply-To"),
                "return_path": get_header("Return-Path"),
                "message_id": get_header("Message-Id"),
                "received": get_header("Received"),
                "list_id": get_header("List-Id"),
                "spf": extract_auth_status(auth_results, "spf"),
                "dkim": extract_auth_status(auth_results, "dkim"),
                "dmarc": extract_auth_status(auth_results, "dmarc"),
                "spam_score": get_header("X-Spam-Score"),
                "spam_status": get_header("X-Spam-Status"),
                "received_spf": get_header("Received-SPF"),
                "auth_results_raw": auth_results,
            }

        emails = [extract_email_data(meta) for meta in metas]
        
        # Filter emails after the specified internal_date
        if after_internal_date:
            after_timestamp = int(after_internal_date)
            emails = [
                email for email in emails 
                if int(email.get("internal_date", 0)) > after_timestamp
            ]
        
        return JSONResponse({
            "count": len(emails), 
            "emails": emails,
            "user_authenticated": True
        })

    except Exception as e:
        raise HTTPException(500, f"Failed to fetch emails: {str(e)}")
    
    
@app.get("/auth/google")
def auth_google():
    f = flow_obj()
    f.redirect_uri = GOOGLE_REDIRECT_URI
    # offline => refresh_token; prompt=consent => force prompt so refresh_token is returned reliably
    url, state = f.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="select_account consent",
    )
    return RedirectResponse(url)

@app.get("/auth/google/callback")
def auth_google_cb(code: str | None = None, state: str | None = None, error: str | None = None):
    """Handle OAuth callback"""
    if error:
        return HTMLResponse(f"""
        <html>
            <head><title>Authentication Error</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #dc3545;">❌ Authentication Failed</h1>
                <p>Error: {error}</p>
                <p><a href="{STREAMLIT_URL}" style="color: #007bff;">Return to App</a></p>
            </body>
        </html>
        """)
    
    if not code:
        return HTMLResponse("""
        <html>
            <head><title>Authentication Error</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #dc3545;">❌ Authentication Failed</h1>
                <p>Missing authorization code. Please try again.</p>
                <p><a href="/auth/google" style="color: #007bff;">Try Again</a></p>
            </body>
        </html>
        """)

    # Exchange code for tokens
    f = flow_obj()
    f.redirect_uri = GOOGLE_REDIRECT_URI
    try:
        f.fetch_token(code=code)
    except Exception as e:
        return HTMLResponse(f"""
        <html>
            <head><title>Authentication Error</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #dc3545;">❌ OAuth Error</h1>
                <p>Failed to exchange authorization code: {str(e)}</p>
                <p><a href="/auth/google" style="color: #007bff;">Try Again</a></p>
            </body>
        </html>
        """)

    creds = f.credentials
    
    user_id = "default_user"  
    user_credentials[user_id] = creds
    save_credentials_to_json(user_id, creds) 

    return HTMLResponse(f"""
    <html>
    <head>
        <title>Authentication Successful</title>
        <!-- Wait ~2 seconds, then go to Streamlit -->
        <meta http-equiv="refresh" content="2; url={STREAMLIT_URL}?authenticated=true">
    </head>
    <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1 style="color: #28a745;">✅ Authentication Successful!</h1>
        <p>You'll be redirected in about 2 seconds…</p>
        <p>If not, <a href="{STREAMLIT_URL}?authenticated=true">click here</a></p>
    </body>
    </html>
    """)


@app.get("/gmail/emails")
def get_gmail_emails(user_id: str = "default_user", max_results: int = 2, after_timestamp: str = None):
    creds = refresh_token_if_needed(user_id)
    
    if not creds:
        raise HTTPException(400, "User not authenticated. Please authenticate first.")
    
    update_last_sync(user_id)  
    
    try:
        # Build Gmail service
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)

        # 1) Get message IDs from INBOX
        query_params = {
            "userId": "me",
            "labelIds": ["INBOX"],
            "maxResults": max_results
        }
        
        # If after_timestamp provided, only get emails after that time
        if after_timestamp:
            query_params["q"] = f"after:{after_timestamp}"
        
        resp = service.users().messages().list(**query_params).execute()
        
        message_ids = [m["id"] for m in resp.get("messages", [])]

        if not message_ids:
            return JSONResponse({"count": 0, "emails": []})

        # 2) Batch fetch metadata
        metas: list[dict] = []

        def _callback(request_id, response, exception):
            if response:
                metas.append(response)
            if exception:
                print(f"Batch request error: {exception}")

        batch = service.new_batch_http_request(callback=_callback)
        for mid in message_ids:
            batch.add(
                service.users().messages().get(
                    userId="me",
                    id=mid,
                    format="metadata",
                    metadataHeaders=[
                        "From", "To", "Subject", "Date", "Message-Id",
                        "Reply-To", "Return-Path", "Received",
                        "Authentication-Results", "List-Id", "X-Spam-Score",
                        "X-Spam-Status", "Received-SPF"
                    ],
                )
            )
        batch.execute()

        # 3) Extract headers and authentication results
        def extract_email_data(message: dict) -> dict:
            headers = {h["name"]: h["value"] for h in message.get("payload", {}).get("headers", [])}
            
            # Extract authentication results
            auth_results = headers.get("Authentication-Results", "") or ""
            
            def get_header(name): 
                return headers.get(name, "")
            
            def extract_auth_status(auth_string, protocol):
                """Extract pass/fail status for SPF, DKIM, DMARC"""
                if f"{protocol}=pass" in auth_string.lower():
                    return "pass"
                elif f"{protocol}=fail" in auth_string.lower():
                    return "fail"
                elif f"{protocol}=neutral" in auth_string.lower():
                    return "neutral"
                elif f"{protocol}=softfail" in auth_string.lower():
                    return "softfail"
                else:
                    return "n/a"
            
            return {
                "id": message.get("id"),
                "thread_id": message.get("threadId"),
                "date": get_header("Date"),
                "internal_date": message.get("internalDate"),  # Gmail's timestamp (milliseconds)
                "from": get_header("From"),
                "to": get_header("To"),
                "subject": get_header("Subject"),
                "reply_to": get_header("Reply-To"),
                "return_path": get_header("Return-Path"),
                "message_id": get_header("Message-Id"),
                "received": get_header("Received"),
                "list_id": get_header("List-Id"),
                "spf": extract_auth_status(auth_results, "spf"),
                "dkim": extract_auth_status(auth_results, "dkim"),
                "dmarc": extract_auth_status(auth_results, "dmarc"),
                "spam_score": get_header("X-Spam-Score"),
                "spam_status": get_header("X-Spam-Status"),
                "received_spf": get_header("Received-SPF"),
                "auth_results_raw": auth_results,
            }

        emails = [extract_email_data(meta) for meta in metas]
        
        return JSONResponse({
            "count": len(emails), 
            "emails": emails,
            "user_authenticated": True
        })

    except Exception as e:
        raise HTTPException(500, f"Failed to fetch emails: {str(e)}")

@app.get("/auth/status")
def auth_status(user_id: str = "default_user"):
    """Check if user is authenticated"""
    is_authenticated = user_id in user_credentials
    return JSONResponse({
        "authenticated": is_authenticated,
        "user_id": user_id if is_authenticated else None
    })

@app.post("/auth/logout")
def logout(user_id: str = "default_user"):
    """Logout user and clear credentials"""
    if user_id in user_credentials:
        del user_credentials[user_id]
    return JSONResponse({"message": "Logged out successfully"})

# ============================================================================
# ANALYSIS RESULTS STORAGE (JSON) - NEW ENDPOINTS
# ============================================================================

@app.post("/analysis/save")
def save_analysis_result(data: dict):
    """Save analysis result to JSON file"""
    analysis_data = load_json_file(ANALYSIS_FILE)
    
    user_id = data.get("user_id", "default_user")
    
    if user_id not in analysis_data["users"]:
        analysis_data["users"][user_id] = {
            "emails": {},
            "stats": {
                "total_analyzed": 0,
                "legit_count": 0,
                "suspicious_count": 0,
                "phishing_count": 0,
                "last_updated": None
            }
        }
    
    email_id = data.get("email_id")
    verdict = data.get("verdict", "")
    
    # Save email analysis
    analysis_data["users"][user_id]["emails"][email_id] = {
        "analyzed_at": datetime.now().isoformat(),
        "verdict": verdict,
        "total_score": data.get("total_score"),
        "from_address": data.get("from_address"),
        "subject": data.get("subject"),
        "date": data.get("date"),
        "gpt_verdict": data.get("gpt_verdict"),
        "gpt_score": data.get("gpt_score"),
        "bert_score": data.get("bert_score"),
        "domain_score": data.get("domain_score")
    }
    
    # Update stats
    stats = analysis_data["users"][user_id]["stats"]
    stats["total_analyzed"] = len(analysis_data["users"][user_id]["emails"])
    stats["legit_count"] = sum(1 for e in analysis_data["users"][user_id]["emails"].values() if "Legit" in e["verdict"])
    stats["suspicious_count"] = sum(1 for e in analysis_data["users"][user_id]["emails"].values() if "Suspicious" in e["verdict"])
    stats["phishing_count"] = sum(1 for e in analysis_data["users"][user_id]["emails"].values() if "Phishing" in e["verdict"])
    stats["last_updated"] = datetime.now().isoformat()
    
    save_json_file(ANALYSIS_FILE, analysis_data)
    
    return {"status": "success", "stats": stats}

@app.get("/analysis/stats")
def get_analysis_stats(user_id: str = "default_user"):
    """Get analysis statistics"""
    analysis_data = load_json_file(ANALYSIS_FILE)
    
    if user_id not in analysis_data.get("users", {}):
        return {
            "total_analyzed": 0,
            "legit_count": 0,
            "suspicious_count": 0,
            "phishing_count": 0,
            "last_updated": None
        }
    
    return analysis_data["users"][user_id]["stats"]

@app.get("/analysis/history")
def get_analysis_history(user_id: str = "default_user", limit: int = 100):
    """Get analysis history"""
    analysis_data = load_json_file(ANALYSIS_FILE)
    
    if user_id not in analysis_data.get("users", {}):
        return {"history": []}
    
    emails = analysis_data["users"][user_id]["emails"]
    
    # Sort by analyzed_at and limit
    history = [
        {
            "email_id": email_id,
            **email_data
        }
        for email_id, email_data in emails.items()
    ]
    
    history.sort(key=lambda x: x["analyzed_at"], reverse=True)
    
    return {"history": history[:limit]}

@app.delete("/analysis/clear")
def clear_analysis_history(user_id: str = "default_user"):
    """Clear analysis history"""
    analysis_data = load_json_file(ANALYSIS_FILE)
    
    if user_id in analysis_data.get("users", {}):
        analysis_data["users"][user_id] = {
            "emails": {},
            "stats": {
                "total_analyzed": 0,
                "legit_count": 0,
                "suspicious_count": 0,
                "phishing_count": 0,
                "last_updated": None
            }
        }
        save_json_file(ANALYSIS_FILE, analysis_data)
    
    return {"status": "cleared"}

@app.get("/analysis/check_analyzed")
def check_if_analyzed(email_id: str, user_id: str = "default_user"):
    """Check if email was already analyzed"""
    analysis_data = load_json_file(ANALYSIS_FILE)
    
    if user_id not in analysis_data.get("users", {}):
        return {"analyzed": False}
    
    is_analyzed = email_id in analysis_data["users"][user_id]["emails"]
    
    if is_analyzed:
        return {
            "analyzed": True,
            "result": analysis_data["users"][user_id]["emails"][email_id]
        }
    
    return {"analyzed": False}

@app.post("/analysis/set_start_time")
def set_start_time():
    """Set the system start time to now (when user enables auto-sync)"""
    analysis_data = load_json_file(ANALYSIS_FILE)
    analysis_data["system_start_time"] = datetime.now().isoformat()
    save_json_file(ANALYSIS_FILE, analysis_data)
    return {"status": "success", "start_time": analysis_data["system_start_time"]}

@app.get("/analysis/start_time")
def get_start_time():
    """Get the system start time"""
    analysis_data = load_json_file(ANALYSIS_FILE)
    start_time = analysis_data.get("system_start_time")
    return {"start_time": start_time}

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "gmail-oauth-backend"}

# CORS middleware for development
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],  # Streamlit default ports
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )