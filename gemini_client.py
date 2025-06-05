# gemini_client.py
import google.generativeai as genai # Correct import for google-genai library
import json
from config import GEMINI_API_KEY, GEMINI_MODEL_NAME

class GeminiClient:
    def __init__(self):
        if not GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY not configured.")

        # Configure using the 'genai' alias from the correct import
        genai.configure(api_key=GEMINI_API_KEY)

        # Use a model that supports function calling
        self.model = genai.GenerativeModel( # Use genai.GenerativeModel
            model_name=GEMINI_MODEL_NAME,
            tools=[{
                "function_declarations": [
                    {
                        "name": "report_threats",
                        "description": "Reports a list of potential security threats detected in the Cloudflare logs.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "threats": {
                                    "type": "array",
                                    "description": "A list of detected threats.",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "client_ip": {
                                                "type": "string",
                                                "description": "The source IP address of the potential threat."
                                            },
                                            "user_agent": {
                                                "type": "string",
                                                "description": "The User-Agent string associated with the potential threat."
                                            },
                                             "asn": {
                                                "type": "string",
                                                "description": "The ASN ID associated with the source IP."
                                            },
                                            "threat_type": {
                                                "type": "string",
                                                "description": "The type of threat detected (e.g., 'dictionary attack', 'suspicious IP pattern', 'WAF bypass attempt')."
                                            },
                                            "description": {
                                                "type": "string",
                                                "description": "A brief description of why this log entry is considered a threat."
                                            }
                                        },
                                        "required": ["client_ip", "threat_type", "description"]
                                    }
                                }
                            },
                            "required": ["threats"]
                        }
                    }
                ]
            }]
        )
        # Start a chat session
        self.chat_session = self.model.start_chat()

    async def analyze_logs(self, log_entries: list):
        """
        Analyzes a batch of log entries using Gemini to identify threats.
        """
        if not log_entries:
            return []

        log_text = json.dumps(log_entries, indent=2)
        prompt = f"""Analyze the following Cloudflare log entries to identify potential security threats,
        such as dictionary attacks, suspicious IP patterns, or attempts to bypass security rules.
        Focus on patterns in ClientIP, ClientRequestUserAgent, ClientASN, FirewallMatchesActions,
        FirewallMatchesSources, WAFAction, WAFRuleID, WAFRuleMessage, and SecurityLevelAction.

        If you detect any threats, use the `report_threats` function to list them.
        If no threats are detected, do not call the function.

        Cloudflare Logs (JSON format):
        ```json
        {log_text}
        ```
        """

        try:
            response = await self.chat_session.send_message_async(prompt)

            if response.candidates and response.candidates[0].content.parts:
                 first_part = response.candidates[0].content.parts[0]
                 # Check for function_call attribute and its name
                 if hasattr(first_part, 'function_call') and hasattr(first_part.function_call, 'name') and first_part.function_call.name == "report_threats":
                    tool_call = first_part.function_call
                    threat_arguments = tool_call.args
                    return threat_arguments.get("threats", [])
                 else:
                    print("Gemini analysis completed, no threats reported by the model via function call.")
                    # You can inspect response.text for non-function call responses
                    # if hasattr(response, 'text'): print(f"Gemini response (text): {response.text}")
                    return []
            
            print("Gemini response structure unexpected or empty (no candidates/parts).")
            return []

        except Exception as e:
            print(f"Error during Gemini analysis: {e}")
            import traceback
            traceback.print_exc()
            return []
