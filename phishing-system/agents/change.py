from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import re

def extract_headers_and_text(eml_path, max_body_chars=20000):
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)


    headers = "\n".join(f"{k}: {v}" for k, v in msg.items())


    from_header = msg.get("From", "")
    match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
    sender_email = match.group(0) if match else None

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and part.get_content():
                body_text += part.get_content()
            elif ctype == "text/html" and not body_text:
                html = part.get_content()
                soup = BeautifulSoup(html, "html.parser")
                for a in soup.find_all("a"):
                    href = a.get("href")
                    if href:
                        a.insert_after(f" ({href})")
                body_text += soup.get_text()
    else:
        content = msg.get_content()
        if msg.get_content_type() == "text/html":
            soup = BeautifulSoup(content, "html.parser")
            for a in soup.find_all("a"):
                if a.get("href"):
                    a.insert_after(f" ({a.get('href')})")
            body_text = soup.get_text()
        else:
            body_text = content

    if len(body_text) > max_body_chars:
        body_text = body_text[:max_body_chars] + "\n...[truncated]..."

    return headers.strip(), body_text.strip(), sender_email


import email
from email import policy
from email.parser import BytesParser
import re
from typing import Dict, Any, List


def extract_email_fields(email_file_path: str) -> Dict[str, Any]:

    # Parse the email
    with open(email_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    # Helper function to extract auth status
    def get_auth_status(auth_results: str, auth_type: str) -> str:
        if not auth_results:
            return 'n/a'
        pattern = rf'{auth_type}=(\w+)'
        match = re.search(pattern, auth_results.lower())
        return match.group(1) if match else 'n/a'
    
    # Helper function to extract domain
    def get_domain(email_address: str) -> str:
        if not email_address:
            return ''
        match = re.search(r'[\w\.-]+@([\w\.-]+)', email_address)
        return match.group(1) if match else ''
    
    # Helper function to extract body
    def get_body(content_type='plain') -> str:
        try:
            body = msg.get_body(preferencelist=(content_type,))
            if body:
                content = body.get_content()
                return content[:10000] if content else ''
        except:
            pass
        return ''
    
    # Helper function to get attachments
    def get_attachments() -> List[Dict[str, str]]:
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                if 'attachment' in str(part.get_content_disposition()):
                    attachments.append({
                        'filename': part.get_filename() or 'unknown',
                        'content_type': part.get_content_type(),
                    })
        return attachments
    
    # Get authentication results for parsing
    auth_results = msg.get('Authentication-Results', '')
    
    # Extract ALL fields
    fields = {
        # Core headers
        'id': msg.get('Message-ID', ''),
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'cc': msg.get('Cc', ''),
        'bcc': msg.get('Bcc', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'sender': msg.get('Sender', ''),
        'in_reply_to': msg.get('In-Reply-To', ''),
        'references': msg.get('References', ''),
        
        # Authentication - Parsed status
        'spf': get_auth_status(auth_results, 'spf'),
        'dkim': get_auth_status(auth_results, 'dkim'),
        'dmarc': get_auth_status(auth_results, 'dmarc'),
        
        # Authentication - Full headers
        'authentication_results': auth_results,
        'received_spf': msg.get('Received-SPF', ''),
        'dkim_signature': msg.get('DKIM-Signature', ''),
        'domainkey_signature': msg.get('DomainKey-Signature', ''),
        
        # ARC (Authenticated Received Chain)
        'arc_seal': msg.get('ARC-Seal', ''),
        'arc_message_signature': msg.get('ARC-Message-Signature', ''),
        'arc_authentication_results': msg.get('ARC-Authentication-Results', ''),
        
        # Routing & Delivery
        'received': msg.get_all('Received', []),
        'received_count': len(msg.get_all('Received', [])),
        'delivered_to': msg.get('Delivered-To', ''),
        'x_original_to': msg.get('X-Original-To', ''),
        'envelope_to': msg.get('Envelope-To', ''),
        'x_forwarded_to': msg.get('X-Forwarded-To', ''),
        'x_forwarded_for': msg.get('X-Forwarded-For', ''),
        
        # Content headers
        'mime_version': msg.get('MIME-Version', ''),
        'content_type': msg.get('Content-Type', ''),
        'content_transfer_encoding': msg.get('Content-Transfer-Encoding', ''),
        'content_disposition': msg.get('Content-Disposition', ''),
        'content_id': msg.get('Content-ID', ''),
        'content_description': msg.get('Content-Description', ''),
        'content_language': msg.get('Content-Language', ''),
        'content_base': msg.get('Content-Base', ''),
        
        # Mailing List headers
        'list_id': msg.get('List-Id', ''),
        'list_help': msg.get('List-Help', ''),
        'list_unsubscribe': msg.get('List-Unsubscribe', ''),
        'list_unsubscribe_post': msg.get('List-Unsubscribe-Post', ''),
        'list_subscribe': msg.get('List-Subscribe', ''),
        'list_post': msg.get('List-Post', ''),
        'list_owner': msg.get('List-Owner', ''),
        'list_archive': msg.get('List-Archive', ''),
        'mailing_list': msg.get('Mailing-List', ''),
        'precedence': msg.get('Precedence', ''),
        
        # Google-specific headers
        'x_google_smtp_source': msg.get('X-Google-Smtp-Source', ''),
        'x_received': msg.get('X-Received', ''),
        'x_google_dkim_signature': msg.get('X-Google-DKIM-Signature', ''),
        'x_gm_message_state': msg.get('X-Gm-Message-State', ''),
        'x_google_id': msg.get('X-Google-Id', ''),
        
        # Spam & Security headers
        'x_spam_score': msg.get('X-Spam-Score', ''),
        'x_spam_status': msg.get('X-Spam-Status', ''),
        'x_spam_flag': msg.get('X-Spam-Flag', ''),
        'x_spam_level': msg.get('X-Spam-Level', ''),
        'x_spam_report': msg.get('X-Spam-Report', ''),
        'x_spam_checker_version': msg.get('X-Spam-Checker-Version', ''),
        'x_virus_scanned': msg.get('X-Virus-Scanned', ''),
        'x_virus_status': msg.get('X-Virus-Status', ''),
        
        # Email Service Provider headers
        'x_msfbl': msg.get('X-MSFBL', ''),  # SparkPost/Microsoft
        'x_sg_eid': msg.get('X-SG-EID', ''),  # SendGrid
        'x_sg_id': msg.get('X-SG-ID', ''),  # SendGrid
        'x_mailgun_variables': msg.get('X-Mailgun-Variables', ''),  # Mailgun
        'x_mailgun_tag': msg.get('X-Mailgun-Tag', ''),  # Mailgun
        'x_mc_user': msg.get('X-MC-User', ''),  # MailChimp
        
        # Tracking headers
        'x_mailer': msg.get('X-Mailer', ''),
        'user_agent': msg.get('User-Agent', ''),
        'x_mailer_version': msg.get('X-Mailer-Version', ''),
        'x_originating_ip': msg.get('X-Originating-IP', ''),
        'x_sender_ip': msg.get('X-Sender-IP', ''),
        'x_source_ip': msg.get('X-Source-IP', ''),
        'x_original_ip': msg.get('X-Original-IP', ''),
        'x_campaign_id': msg.get('X-Campaign-ID', ''),
        'x_campaign': msg.get('X-Campaign', ''),
        'x_track': msg.get('X-Track', ''),
        
        # Priority & Importance
        'priority': msg.get('Priority', ''),
        'importance': msg.get('Importance', ''),
        'x_priority': msg.get('X-Priority', ''),
        'x_msmail_priority': msg.get('X-MSMail-Priority', ''),
        
        # Auto-reply & Notification
        'auto_submitted': msg.get('Auto-Submitted', ''),
        'x_auto_response_suppress': msg.get('X-Auto-Response-Suppress', ''),
        'x_autorespond': msg.get('X-Autorespond', ''),
        
        # Organization
        'organization': msg.get('Organization', ''),
        'x_organization': msg.get('X-Organization', ''),
        'x_company': msg.get('X-Company', ''),
        'x_authenticated_user': msg.get('X-Authenticated-User', ''),
        'x_originating_email': msg.get('X-Originating-Email', ''),
        
        # Microsoft Exchange/Outlook
        'thread_topic': msg.get('Thread-Topic', ''),
        'thread_index': msg.get('Thread-Index', ''),
        'accept_language': msg.get('Accept-Language', ''),
        'x_ms_has_attach': msg.get('X-MS-Has-Attach', ''),
        'content_class': msg.get('Content-Class', ''),
        
        # Mobile/Device
        'x_device': msg.get('X-Device', ''),
        'x_client': msg.get('X-Client', ''),
        
        # Anti-Spam Filters
        'x_rbl_warning': msg.get('X-RBL-Warning', ''),
        'x_barracuda_spam_score': msg.get('X-Barracuda-Spam-Score', ''),
        'x_barracuda_spam_status': msg.get('X-Barracuda-Spam-Status', ''),
        'x_proofpoint_virus_version': msg.get('X-Proofpoint-Virus-Version', ''),
        'x_proofpoint_spam_details': msg.get('X-Proofpoint-Spam-Details', ''),
        'x_ironport_anti_spam_filtered': msg.get('X-IronPort-Anti-Spam-Filtered', ''),
        'x_ironport_anti_spam_result': msg.get('X-IronPort-Anti-Spam-Result', ''),
        
        # Domain extraction
        'sender_domain': get_domain(msg.get('From', '')),
        'return_path_domain': get_domain(msg.get('Return-Path', '')),
        'reply_to_domain': get_domain(msg.get('Reply-To', '')),
        
        # Body content
        'body_plain': get_body('plain'),
        'body_html': get_body('html'),
        
        'attachments': get_attachments(),
        'has_attachments': len(get_attachments()) > 0,
        'attachment_count': len(get_attachments()),
        
        # Metadata
        'is_multipart': msg.is_multipart(),
    }
    
    return fields