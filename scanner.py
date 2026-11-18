import os
import imaplib
import email
from email.header import decode_header
import re
import hashlib
import base64
import time
import html
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
APP_PASSWORD = os.getenv("APP_PASSWORD")
VT_API_KEY = os.getenv("VT_API_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
QUARANTINE_FOLDER = "Phishing_Quarantine"

SUSPICIOUS_KEYWORDS = [
    "təcili", "hesabınız bloklanacaq", "şifrəni yenilə", "təsdiqləyin",
    "urgent", "verify your account", "suspended", "login immediately",
    "bank hesabınız", "pul köçürməsi", "uduş", "faktura"
]
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".zip"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
DANGEROUS_EXTENSIONS = {".exe", ".vbs", ".js", ".bat", ".scr", ".iso", ".ps1", ".jar", ".cmd"}


def send_telegram_alert(sender, subject, score, reasons):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    safe_sender = html.escape(sender)
    safe_subject = html.escape(subject)
    formatted_reasons = "\n".join([f"• {html.escape(r)}" for r in reasons])

    message = (
        f"🚨 <b>FİŞİNQ MƏKTUBU BLOKLANDI</b>\n\n"
        f"<b>Göndərən:</b> <code>{safe_sender}</code>\n"
        f"<b>Mövzu:</b> {safe_subject}\n"
        f"<b>Risk balı:</b> {score}\n\n"
        f"<b>Aşkarlanan təhlükələr:</b>\n{formatted_reasons}"
    )
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(api_url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}, timeout=10)
    except requests.RequestException as e:
        print(f"Telegram xətası: {e}", flush=True)


def decode_mime_words(text):
    if not text:
        return ""
    result = ""
    for fragment, encoding in decode_header(text):
        if isinstance(fragment, bytes):
            result += fragment.decode(encoding or "utf-8", errors="ignore")
        else:
            result += fragment
    return result


def extract_urls(text):
    return list(set(re.findall(r'https?://[^\s<>"\']+', text)))


def check_url_virustotal(url):
    if not VT_API_KEY:
        return 0
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if res.status_code == 200:
            stats = res.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) + stats.get("suspicious", 0)
        elif res.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
    except requests.RequestException:
        pass
    return 0


def check_file_hash_virustotal(file_bytes):
    if not VT_API_KEY:
        return 0
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256_hash}", headers=headers, timeout=10)
        if res.status_code == 200:
            stats = res.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except requests.RequestException:
        pass
    return 0


def analyze_email(msg):
    risk_score = 0
    reasons = []

    subject = decode_mime_words(msg.get("Subject", ""))
    from_header = decode_mime_words(msg.get("From", ""))
    reply_to = decode_mime_words(msg.get("Reply-To", ""))
    auth_results = msg.get("Authentication-Results", "").lower()

    if "spf=fail" in auth_results or "spf=softfail" in auth_results:
        risk_score += 3
        reasons.append("SPF autentifikasiyası uğursuz oldu")
    if "dkim=fail" in auth_results:
        risk_score += 3
        reasons.append("DKIM imzası etibarsızdır")

    from_match = re.search(r'<(.+?)>', from_header)
    from_addr = from_match.group(1) if from_match else from_header

    if reply_to and from_addr not in reply_to:
        risk_score += 2
        reasons.append(f"From ({from_addr}) və Reply-To ({reply_to}) fərqlidir")

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            c_type = part.get_content_type()
            c_disp = str(part.get("Content-Disposition", ""))
            if "attachment" in c_disp:
                filename = decode_mime_words(part.get_filename())
                if filename:
                    ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
                    if ext in DANGEROUS_EXTENSIONS:
                        risk_score += 5
                        reasons.append(f"Təhlükəli fayl uzantısı: {filename}")
                    file_data = part.get_payload(decode=True)
                    if file_data:
                        vt_det = check_file_hash_virustotal(file_data)
                        if vt_det > 0:
                            risk_score += 10
                            reasons.append(f"VirusTotal zərərli fayl aşkarladı ({vt_det} mühərrik): {filename}")
                        time.sleep(15)
            elif c_type in ["text/plain", "text/html"]:
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")

    full_text = f"{subject} {body}".lower()
    matched_words = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_text]
    if matched_words:
        risk_score += len(matched_words)
        reasons.append(f"Şübhəli açar sözlər: {', '.join(matched_words)}")

    for url in extract_urls(body):
        domain = urlparse(url).netloc.lower()
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            risk_score += 4
            reasons.append(f"Birbaşa IP ünvanlı link: {url}")
        if any(short in domain for short in URL_SHORTENERS):
            risk_score += 2
            reasons.append(f"Qısaldılmış link: {url}")
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            risk_score += 2
            reasons.append(f"Şübhəli domen zonası: {domain}")

        vt_url_det = check_url_virustotal(url)
        if vt_url_det > 0:
            risk_score += 10
            reasons.append(f"VirusTotal zərərli link aşkarladı ({vt_url_det} mühərrik): {url}")
        time.sleep(15)

    return risk_score, reasons, subject, from_addr


def process_inbox():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ACCOUNT, APP_PASSWORD)
    mail.create(QUARANTINE_FOLDER)
    mail.select("inbox")

    _, messages = mail.search(None, "UNSEEN")
    for e_id in messages[0].split():
        _, msg_data = mail.fetch(e_id, "(RFC822)")
        msg = email.message_from_bytes(msg_data[0][1])

        score, reasons, subject, sender = analyze_email(msg)
        print(f"[ANALİZ] '{subject}' | Göndərən: {sender} | Risk: {score}", flush=True)

        if score >= 4:
            print(f"  -> [BLOKLANDI] Səbəblər: {'; '.join(reasons)}", flush=True)
            if mail.copy(e_id, QUARANTINE_FOLDER)[0] == "OK":
                mail.store(e_id, "+FLAGS", "\\Deleted")
                send_telegram_alert(sender, subject, score, reasons)

    mail.expunge()
    mail.logout()


if __name__ == "__main__":
    print("Fişinq Mühafizə Sistemi işə düşdü...", flush=True)
    while True:
        try:
            process_inbox()
        except Exception as e:
            print(f"Xəta baş verdi: {e}", flush=True)
        time.sleep(15)
