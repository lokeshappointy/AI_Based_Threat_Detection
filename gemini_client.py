# gemini_client.py
import google.generativeai as genai
import json
from config import GEMINI_API_KEY, GEMINI_MODEL_NAME

class GeminiClient:
    def __init__(self):
        if not GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY not configured.")

        genai.configure(api_key=GEMINI_API_KEY)

        self.model = genai.GenerativeModel(
            model_name=GEMINI_MODEL_NAME,
            tools=[{
                "function_declarations": [
                    {
                        "name": "report_suspicious_activity",
                        "description": "Reports distinct suspicious entities or behaviors found in HTTP request logs.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "threats": {
                                    "type": "array",
                                    "description": "A list of distinct suspicious entities and reasoning.",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "entity_type": {
                                                "type": "string",
                                                "description": "The kind of suspicious entity (IP, UserAgent, ASN, URI_Pattern, RequestPattern)."
                                            },
                                            "entity_value": {
                                                "type": "string",
                                                "description": "The exact value of the suspicious entity (e.g., IP address, UserAgent string)."
                                            },
                                            "reason": {
                                                "type": "string",
                                                "description": "Concise reason why this entity is suspicious."
                                            },
                                            "suggested_action": {
                                                "type": "string",
                                                "description": "Recommended WAF action (e.g., block, challenge)."
                                            },
                                            "confidence_score": {
                                                "type": "number",
                                                "description": "A float between 0 and 1 representing the confidence level."
                                            }
                                        },
                                        "required": ["entity_type", "entity_value", "reason", "suggested_action", "confidence_score"]
                                    }
                                }
                            },
                            "required": ["threats"]
                        }
                    }
                ]
            }]
        )

        self.chat_session = self.model.start_chat()

    async def analyze_logs(self, log_entries: list):
        """
        Analyzes a batch of log entries using Gemini to identify suspicious activity.
        """
        if not log_entries:
            return []

        log_text = json.dumps(log_entries, indent=2)
        prompt = (
            "You are an expert cybersecurity threat detection analyst. Your primary function is to meticulously analyze "
            "the provided batch of Cloudflare HTTP request log entries to identify sophisticated and emerging threats, "
            "including but not limited to: coordinated dictionary attacks (e.g., multiple POSTs to /login, /admin, /signin, /wp-login.php from an IP/ASN with many 4xx responses), "
            "SQL injection attempts (e.g., URI queries containing 'UNION SELECT', 'DROP TABLE', or SQL-like syntax), "
            "Local/Remote File Inclusion (e.g., '../', 'etc/passwd'), "
            "Cross-Site Scripting (XSS) payloads (e.g., '<script>', 'onerror='), "
            "User-Agents known to be scanners or malicious bots (e.g., 'sqlmap', 'Nmap Scripting Engine', 'masscan', 'dirb', 'nikto', 'Havij', known bad bot strings), "
            "or IPs/ASNs generating an unusually high rate of HTTP error codes (401, 403, 404, 429, 5xx) particularly to sensitive paths. "
            "Also, consider IPs making requests to common vulnerability probing paths (e.g., '/.env', '/config/backup.zip', '/phpmyadmin/'), "
            "or IPs exhibiting a high request rate that could indicate a denial-of-service or brute-force attack.

"
            "For each distinct suspicious activity or entity you identify with high confidence (e.g., confidence > 0.7), "
            "YOU MUST use the 'report_suspicious_activity' tool. Provide the entity type (IP, UserAgent, ASN, URI_Pattern for specific paths, RequestPattern for method+path), "
            "the entity value, a concise reason based on the log data (e.g., 'Multiple 403s to /admin from this IP', 'High request rate from IP', 'SQLi signature in URI query', 'User agent is a known scanner'), "
            "a suggested Cloudflare WAF action ('block', 'challenge'), and a confidence_score.

"
            f"Log Data Batch Sample (focus your analysis on these entries):
```json
{log_text}
```"
        )

        try:
            response = await self.chat_session.send_message_async(prompt)

            if response.candidates and response.candidates[0].content.parts:
                first_part = response.candidates[0].content.parts[0]
                if hasattr(first_part, 'function_call') and hasattr(first_part.function_call, 'name') and first_part.function_call.name == "report_suspicious_activity":
                    tool_call = first_part.function_call
                    threat_arguments = tool_call.args
                    return threat_arguments.get("threats", [])
                else:
                    print("Gemini analysis completed, no threats reported by the model via function call.")
                    return []

            print("Gemini response structure unexpected or empty (no candidates/parts).")
            return []

        except Exception as e:
            print(f"Error during Gemini analysis: {e}")
            import traceback
            traceback.print_exc()
            return []
