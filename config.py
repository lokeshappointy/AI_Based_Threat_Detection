# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# --- Cloudflare API Configuration ---
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CLOUDFLARE_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")


# --- Gemini AI Configuration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_NAME = "gemini-2.5-pro-preview-05-06"     # Or "gemini-pro", "gemini-1.5-pro-latest"

# --- Instant Logs Configuration ---
# Define the fields you want to receive for threat detection.
LOG_FIELDS_LIST = [
    "RayID",
    "EdgeStartTimestamp",
    "ClientIP",
    "ClientRequestHost",
    "ClientRequestMethod",
    "ClientRequestURI",
    "EdgeResponseStatus",
    "ClientCountry",
    "ClientASN",
    "ClientASNDescription",
    "ClientRequestUserAgent",
    "FirewallMatchesActions",   # e.g., ["block", "challenge"]
    "FirewallMatchesRuleIDs", # Which of your existing rules fired
    "FirewallMatchesSources", # e.g., ["custom", "waf", "ratelimit"]
    "WAFAction",              # Action by OWASP or WAF managed ruleset
    "WAFRuleID",              # ID of the OWASP/managed rule
    "WAFRuleMessage",         # Message of the OWASP/managed rule
    "SecurityLevelAction",    # Action by Security Level (low, medium, high, iuam)
    "ClientRequestReferer",
    "ClientRequestBytes",
    "EdgeResponseBytes",
]
LOG_FIELDS = ",".join(LOG_FIELDS_LIST)

LOG_FILTER_JSON_STRING = "" # Start broad, refine later
LOG_SAMPLE_RATE = 100

# --- Session Management ---
SESSION_RENEWAL_INTERVAL_MINUTES = 55

# --- Log Batching for AI Analysis ---
MAX_LOG_BATCH_SIZE = 15  # Adjust based on typical log entry size and Gemini token limits
BATCH_FLUSH_INTERVAL_SECONDS = 15 # Adjust

# --- Output Log File (Optional for raw logs) ---
OUTPUT_LOG_FILE = "received_cloudflare_logs.ndjson" 

# --- Delays ---
RETRY_DELAY_SECONDS = 30
WEBSOCKET_ERROR_RETRY_DELAY_SECONDS = 10