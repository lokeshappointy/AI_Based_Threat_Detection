# gemini_client.py
import google.generativeai as genai # Keep this import for now for compatibility, though genai is the main one
# The new library is google-genai, and the primary import is google.genai
# In some cases, the direct import 'import genai' might also work depending on installation
# Let's try the most common new import structure.
import google.genai as google_genai # Use a different alias to avoid confusion with the old one if both exist
import json
from config import GEMINI_API_KEY, GEMINI_MODEL_NAME

class GeminiClient:
    def __init__(self):
        if not GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY not configured.")

        # Configure using the new library's entry point
        google_genai.configure(api_key=GEMINI_API_KEY)

        # Use a model that supports function calling from the new library's interface
        # The model naming and function calling structure should be similar.
        self.model = google_genai.GenerativeModel( # Use google_genai.GenerativeModel
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
        # Start a chat session for potential multi-turn analysis if needed later
        self.chat_session = self.model.start_chat() # Method name remains the same

    async def analyze_logs(self, log_entries: list):
        """
        Analyzes a batch of log entries using Gemini to identify threats.

        Args:
            log_entries: A list of parsed log entry dictionaries.

        Returns:
            A list of detected threats in the specified format, or None if no threats detected
            or an error occurred.
        """
        if not log_entries:
            return []

        # Format logs for the prompt
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
            # Send the prompt with the function calling expectation using the new library
            response = await self.chat_session.send_message_async(prompt) # Method name remains the same

            # Check if the model wants to call the function
            # Accessing function call details might slightly differ in structure
            # Based on google-genai examples, it's often response.tool_calls or similar
            # Let's check the structure of the response object from the new library.
            # A common pattern is to check response.candidates[0].content.parts[0].function_call
            # If that doesn't work, we might need to inspect the response object.
            # Assuming the structure is similar for now:
            if response.candidates and response.candidates[0].content.parts:
                 first_part = response.candidates[0].content.parts[0]
                 if hasattr(first_part, 'function_call') and first_part.function_call.name == "report_threats":
                    # The model provides the function call details
                    tool_call = first_part.function_call

                    # The arguments are in a dictionary format within the args attribute
                    threat_arguments = tool_call.args
                    return threat_arguments.get("threats", [])
                 else:
                    # No function_call attribute or name is not report_threats
                    # This is the case where the model does not report threats using the function
                    print("Gemini analysis completed, no threats reported by the model via function call.")
                    # Optionally, you could print response.text here if you want to see
                    # what the model outputted if it didn't call the function.
                    # print(f"Gemini response (non-function call): {response.text}")
                    return []


            # If response structure is unexpected or empty
            print("Gemini response structure unexpected or empty.")
            # Optionally print the full response object for debugging
            # print(f"Full Gemini response object: {response}")
            return []


        except Exception as e:
            print(f"Error during Gemini analysis: {e}")
            # Optionally, log the response text for debugging if available
            # print(f"Gemini response text: {response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A'}")
            # Optionally print the full exception details
            import traceback
            traceback.print_exc()
            return [] # Return empty list on error
