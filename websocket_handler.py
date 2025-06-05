# websocket_handler.py
import asyncio
import websockets # Import the top-level module
import json
import time
from datetime import datetime, timezone, timedelta

# Import Gemini specific libraries
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold, FunctionDeclaration

from config import (
    SESSION_RENEWAL_INTERVAL_MINUTES,
    OUTPUT_LOG_FILE,
    WEBSOCKET_ERROR_RETRY_DELAY_SECONDS,
    MAX_LOG_BATCH_SIZE,
    BATCH_FLUSH_INTERVAL_SECONDS,
    LOG_FIELDS_LIST,
    GEMINI_API_KEY,
    GEMINI_MODEL_NAME
)

# --- Configure Gemini ---
GEMINI_ENABLED = False
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        GEMINI_ENABLED = True
        print("Gemini API configured successfully.")
    except Exception as e:
        print(f"ERROR: Failed to configure Gemini API: {e}. AI analysis will be disabled.")
else:
    print("WARNING: GEMINI_API_KEY not found in environment. AI analysis will be skipped.")

# --- Gemini Tool (Function Declaration) Definition ---
report_suspicious_activity_func_declaration = FunctionDeclaration(
    name="report_suspicious_activity",
    description=(
        "Reports suspicious activities detected in a batch of Cloudflare log entries. "
        "For each distinct suspicious entity or pattern, provide the entity type (IP, UserAgent, ASN, URI_Pattern, RequestPattern), "
        "the specific entity value, a brief reason for suspicion based on the logs, "
        "and a suggested Cloudflare WAF action (e.g., block, challenge, managed_challenge, js_challenge)."
    ),
    parameters={ # This is now a Python dictionary
        "type": "OBJECT", # Use uppercase strings for types as per OpenAPI Schema for Gemini
        "properties": {
            "findings": {
                "type": "ARRAY",
                "description": "A list of detected suspicious findings.",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "entity_type": {"type": "STRING", "description": "Type of the suspicious entity (e.g., IP, UserAgent, ASN, URI_Pattern, RequestPattern)."},
                        "entity_value": {"type": "STRING", "description": "The specific value of the suspicious entity."},
                        "reason": {"type": "STRING", "description": "Brief justification for why this entity/pattern is considered suspicious."},
                        "suggested_action": {"type": "STRING", "description": "Suggested Cloudflare WAF action."},
                        "confidence_score": {"type": "NUMBER", "description": "A score from 0.0 to 1.0 indicating confidence (optional)."}
                    },
                    "required":["entity_type", "entity_value", "reason", "suggested_action"]
                }
            }
        },
        "required": ["findings"]
    }
)

GEMINI_SAFETY_SETTINGS = {
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

async def analyze_batch_with_ai(processed_log_batch):
    print("DEBUG: Entered analyze_batch_with_ai")
    if not GEMINI_ENABLED:
        print("SIMULATING AI ANALYSIS: Gemini API not configured or enabled.")
        return {"findings": []}
    if not processed_log_batch:
        print("No processed logs to send to Gemini for analysis.")
        return {"findings": []}

    print(f"--- Sending batch of {len(processed_log_batch)} processed logs to Gemini ({GEMINI_MODEL_NAME}) ---")
    
    detailed_logs_for_prompt = [] 
    MAX_DETAILED_LOGS_IN_PROMPT = 15

    for i, log_event in enumerate(processed_log_batch):
        event_str = (
            f"Event Index: {i+1}\n"
            f"  Timestamp: {log_event.get('EdgeStartTimestamp', 'N/A')}\n"
            f"  ClientIP: {log_event.get('ClientIP', 'N/A')}\n"
            f"  ASN: {log_event.get('ClientASN', 'N/A')} ({log_event.get('ClientASNDescription', 'N/A')})\n"
            f"  Country: {log_event.get('ClientCountry', 'N/A')}\n"
            f"  UserAgent: {log_event.get('ClientRequestUserAgent', 'N/A')}\n"
            f"  Host: {log_event.get('ClientRequestHost', 'N/A')}\n"
            f"  Method: {log_event.get('ClientRequestMethod', 'N/A')}\n"
            f"  URI: {log_event.get('ClientRequestURI', 'N/A')}\n"
            f"  Status: {log_event.get('EdgeResponseStatus', 'N/A')}\n"
            f"  Referer: {log_event.get('ClientRequestReferer', 'N/A')}\n"
            f"  Request Bytes: {log_event.get('ClientRequestBytes', 'N/A')}\n"
            f"  Firewall Actions Matched: {log_event.get('FirewallMatchesActions', [])}\n"
            f"  WAF Action (Managed): {log_event.get('WAFAction', 'None')}\n"
            f"  WAF Rule ID (Managed): {log_event.get('WAFRuleID', 'None')}\n"
            f"  Security Level Action: {log_event.get('SecurityLevelAction', 'None')}\n"
        )
        detailed_logs_for_prompt.append(event_str)
        if len(detailed_logs_for_prompt) >= MAX_DETAILED_LOGS_IN_PROMPT:
            print(f"DEBUG: Reached MAX_DETAILED_LOGS_IN_PROMPT ({MAX_DETAILED_LOGS_IN_PROMPT})")
            break
            
    log_data_segment_for_prompt = "\n---\n".join(detailed_logs_for_prompt)
    if not detailed_logs_for_prompt:
        log_data_segment_for_prompt = "(No detailed log events to display in this segment of the batch)"

    if len(processed_log_batch) > len(detailed_logs_for_prompt): # Check against actual logs added
        log_data_segment_for_prompt += f"\n... (plus {len(processed_log_batch) - len(detailed_logs_for_prompt)} more log entries in this batch not shown in detail)"
    
    prompt = (
        "You are an expert cybersecurity threat detection analyst. Your primary function is to meticulously analyze "
        "the provided batch of Cloudflare HTTP request log entries to identify sophisticated and emerging threats, "
        "including but not limited to: coordinated dictionary attacks (e.g., multiple POSTs to /login, /admin, /signin, /wp-login.php from an IP/ASN with many 4xx responses), "
        "SQL injection attempts (e.g., URI queries containing 'UNION SELECT', 'DROP TABLE', or SQL-like syntax), "
        "Local/Remote File Inclusion (e.g., ' ../', 'etc/passwd'), "
        "Cross-Site Scripting (XSS) payloads (e.g., '<script>', 'onerror='), "
        "User-Agents known to be scanners or malicious bots (e.g., 'sqlmap', 'Nmap Scripting Engine', 'masscan', 'dirb', 'nikto', 'Havij', known bad bot strings), "
        "or IPs/ASNs generating an unusually high rate of HTTP error codes (401, 403, 404, 429, 5xx) particularly to sensitive paths. "
        "Also, consider IPs making requests to common vulnerability probing paths (e.g., '/.env', '/config/backup.zip', '/phpmyadmin/').\n\n"
        "For each distinct suspicious activity or entity you identify with high confidence (e.g., confidence > 0.7), "
        "YOU MUST use the 'report_suspicious_activity' tool. Provide the entity type (IP, UserAgent, ASN, URI_Pattern for specific paths, RequestPattern for method+path), "
        "the entity value, a concise reason based on the log data (e.g., 'Multiple 403s to /admin from this IP', 'SQLi signature in URI query', 'User agent is a known scanner'), "
        "a suggested Cloudflare WAF action ('block', 'challenge'), and a confidence_score.\n\n"
        f"Log Data Batch Sample (focus your analysis on these entries):\n{log_data_segment_for_prompt}"
    )

    max_retries = 3
    retry_delay = 5 # seconds
    for attempt in range(max_retries):
        try:
            model = genai.GenerativeModel(
                model_name=GEMINI_MODEL_NAME,
                tools=[report_suspicious_activity_func_declaration],
                safety_settings=GEMINI_SAFETY_SETTINGS,
                generation_config={"temperature": 0.3}
                # tool_config removed as it was causing AttributeError
            )
            print(f"Sending prompt to Gemini ({GEMINI_MODEL_NAME}), attempt {attempt + 1}/{max_retries}...")
            response = await model.generate_content_async(prompt)
            
            if response.candidates and response.candidates[0].content.parts:
                for part in response.candidates[0].content.parts:
                    if hasattr(part, 'function_call') and part.function_call.name == "report_suspicious_activity":
                        function_call = part.function_call
                        findings_dict = {}
                        # Iterate over function_call.args which is a Struct (like a dict)
                        for key, value_struct in function_call.args.items():
                            if key == "findings": 
                                findings_list = []
                                if isinstance(value_struct, list): # value_struct is a list of Structs
                                    for item_struct in value_struct:
                                        # Convert each Struct in the list to a Python dict
                                        item_dict = {k_inner: v_inner for k_inner, v_inner in item_struct.items()}
                                        findings_list.append(item_dict)
                                findings_dict[key] = findings_list
                            else: # Should not happen if schema is correct and model follows it
                                findings_dict[key] = [] 
                        
                        print("--- Gemini Extracted Findings ---")
                        print(json.dumps(findings_dict, indent=2))
                        print("DEBUG: Exiting analyze_batch_with_ai (successfully got findings)")
                        return findings_dict # Success, exit retry loop
                
                # If loop completes without finding the function call in any part
                print("Warning: Gemini did not call the 'report_suspicious_activity' function as expected (after checking all parts).")
                try: print(f"Gemini's response text: {response.text}")
                except ValueError: print("(No direct text response, and function call was not made as expected)")
                # print(f"Detailed Candidate Parts: {response.candidates[0].content.parts}") # For more debug

            else: # No candidates or no parts
                print("Warning: Gemini response was empty or did not contain expected candidate parts.")
                # print(f"Full Gemini Response: {response}") # For more debug
            
            # If we reach here, the API call was successful but no function call was made as expected
            print("DEBUG: Exiting analyze_batch_with_ai (API call succeeded, but no function call / empty findings)")
            return {"findings": []} 

        except google.api_core.exceptions.InternalServerError as e:
            print(f"Gemini API Internal Server Error (500): {e}. Attempt {attempt + 1}/{max_retries}.")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2 # Exponential backoff
            else:
                print("Max retries reached for Gemini API call due to InternalServerError.")
                import traceback
                traceback.print_exc()
                return {"findings": []}
        except google.api_core.exceptions.ResourceExhausted as e:
            print(f"Gemini API Resource Exhausted (429): {e}. This likely means quota issues or rate limits.")
            print("Please check your GCP project billing and quotas for Gemini.")
            import traceback
            traceback.print_exc()
            return {"findings": []} # Non-retryable from script side for this error
        except Exception as e: # Catch other potential API call errors
            print(f"An unexpected error occurred during Gemini API call: {type(e).__name__} - {e}")
            import traceback
            traceback.print_exc()
            # Decide if this specific error is retryable
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds due to general error...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2 
            else:
                print("Max retries reached for Gemini API call due to general error.")
                return {"findings": []}
    
    print("DEBUG: Exiting analyze_batch_with_ai (after retry loop or other primary failure)")
    return {"findings": []} # Default return if all retries fail


def handle_ai_analysis_results(analysis_results):
    if analysis_results and analysis_results.get("findings"):
        print(f"--- Processing AI Findings for Rule Generation ---")
        findings = analysis_results.get("findings", [])
        if not findings:
            print("No suspicious findings reported by AI.")
            return
        
        # #ToDo: Import or define create_waf_rule_object and update_tfvars_file
        # from rule_utils import create_waf_rule_object, update_tfvars_file (example)
        
        ai_generated_tf_rules = []
        for finding in findings: # Each 'finding' is now a Python dict
            print(f"  AI Finding: Entity='{finding.get('entity_value')}', Type='{finding.get('entity_type')}', Reason='{finding.get('reason')}', Action='{finding.get('suggested_action')}'")
            
            action_to_take = finding.get("suggested_action", "challenge").lower()
            if action_to_take not in ["block", "challenge", "managed_challenge", "js_challenge"]:
                action_to_take = "challenge"

            entity_type = finding.get("entity_type")
            entity_value = finding.get("entity_value")
            
            # TODo: This is where you'd call your create_waf_rule_object
            # rule_dict = create_waf_rule_object(
            #     entity_type=entity_type,
            #     entity_value=entity_value,
            #     action=action_to_take,
            #     description_prefix=f"AI ({GEMINI_MODEL_NAME}): {finding.get('reason', '')[:50]} - ",
            #     target_host="your_target_host_from_config_or_context" # e.g., config.TARGET_HOST
            # )
            # if rule_dict: 
            #    ai_generated_tf_rules.append(rule_dict)
            pass 

        if ai_generated_tf_rules:
            print(f"  --> SIMULATING: Would generate {len(ai_generated_tf_rules)} TF rule objects.")
            # tfvars_path = "cloudflare/zones/appointy_com/appointy_com.tfvars" # Or get dynamically
            # update_tfvars_file(tfvars_path, ai_generated_tf_rules)
        else:
            print("  --> No new TF rule objects generated from AI findings this cycle.")
    else:
        print("No analysis results from AI to process.")

PROCESSED_LOG_BATCH = []
LAST_BATCH_FLUSH_TIME = time.time()

async def process_and_flush_batch():
    global PROCESSED_LOG_BATCH, LAST_BATCH_FLUSH_TIME
    if not PROCESSED_LOG_BATCH: return
    batch_to_analyze = list(PROCESSED_LOG_BATCH)
    PROCESSED_LOG_BATCH.clear()
    LAST_BATCH_FLUSH_TIME = time.time()
    # print(f"--- Flushing batch of {len(batch_to_analyze)} processed logs for AI analysis (DEBUG from process_and_flush_batch) ---")
    ai_results = await analyze_batch_with_ai(batch_to_analyze)
    if ai_results: handle_ai_analysis_results(ai_results)
    # print("DEBUG: Exiting process_and_flush_batch")

async def handle_log_message(message_str, log_file_handle):
    global PROCESSED_LOG_BATCH
    # print("DEBUG: Entered handle_log_message")
    try:
        raw_log_entry = json.loads(message_str)
        if log_file_handle and OUTPUT_LOG_FILE:
            log_file_handle.write(message_str + '\n')
            log_file_handle.flush()
        processed_event = {field: raw_log_entry[field] for field in LOG_FIELDS_LIST if field in raw_log_entry}
        if processed_event: PROCESSED_LOG_BATCH.append(processed_event)
        if len(PROCESSED_LOG_BATCH) >= MAX_LOG_BATCH_SIZE:
            # print(f"Max batch size ({MAX_LOG_BATCH_SIZE}) reached (DEBUG from handle_log_message).")
            await process_and_flush_batch()
    except json.JSONDecodeError: print(f"WARNING: Could not decode JSON: {message_str[:200]}...")
    except Exception as e: 
        print(f"ERROR: Processing log message: {type(e).__name__} - {e}")
        # import traceback
        # traceback.print_exc()
    # print("DEBUG: Exiting handle_log_message")

class WebSocketLogReceiver:
    def __init__(self, websocket_url: str, session_id: str, shutdown_event_param: asyncio.Event):
        self.websocket_url = websocket_url
        self.session_id = session_id
        self.shutdown_event = shutdown_event_param
        self.session_start_time = datetime.now(timezone.utc)
        self._log_file_handle = None
        self._websocket_connection = None

    async def _connect_and_listen(self):
        global LAST_BATCH_FLUSH_TIME, PROCESSED_LOG_BATCH
        # print("DEBUG: Entered _connect_and_listen")
        try:
            if OUTPUT_LOG_FILE:
                try:
                    self._log_file_handle = open(OUTPUT_LOG_FILE, "a")
                    print(f"Opened log file for appending: {OUTPUT_LOG_FILE}")
                except Exception as e:
                    print(f"ERROR: Could not open log file {OUTPUT_LOG_FILE}: {e}")
                    self._log_file_handle = None
            
            self._websocket_connection = await websockets.connect(
                self.websocket_url, ping_interval=20, ping_timeout=20, open_timeout=30
            )
            print(f"Successfully connected to WebSocket for session: {self.session_id} via {getattr(self._websocket_connection, 'id', 'N/A')}")
            self.session_start_time = datetime.now(timezone.utc)
            LAST_BATCH_FLUSH_TIME = time.time() 

            while not self.shutdown_event.is_set():
                # print("DEBUG: Top of _connect_and_listen while loop")
                if datetime.now(timezone.utc) - self.session_start_time > \
                   timedelta(minutes=SESSION_RENEWAL_INTERVAL_MINUTES):
                    print(f"INFO: Session renewal interval reached for {self.session_id}. Ending current session.")
                    break
                
                try:
                    message = await asyncio.wait_for(self._websocket_connection.recv(), timeout=1.0)
                    # print("DEBUG: Message received from websocket")
                    await handle_log_message(message, self._log_file_handle)
                except asyncio.TimeoutError:
                    # print("DEBUG: Websocket recv timed out (normal for no messages)")
                    if PROCESSED_LOG_BATCH and (time.time() - LAST_BATCH_FLUSH_TIME) >= BATCH_FLUSH_INTERVAL_SECONDS:
                        # print(f"Batch flush interval ({BATCH_FLUSH_INTERVAL_SECONDS}s) reached with {len(PROCESSED_LOG_BATCH)} logs (DEBUG from timeout).")
                        await process_and_flush_batch()
                    continue
                except websockets.ConnectionClosedOK:
                    print(f"INFO: WebSocket connection {self.session_id} closed normally by server (1000 OK).")
                    break
                except websockets.ConnectionClosedError as e:
                    print(f"WARNING: WebSocket connection {self.session_id} closed with error by server: Code {e.code}, Reason: '{e.reason}'")
                    break
                except asyncio.CancelledError:
                    print(f"WebSocket recv task for session {self.session_id} was cancelled.")
                    raise 
                except Exception as e_recv: # Catch other errors during recv or handle_log_message
                    print(f"ERROR: During recv/handle_log_message for session {self.session_id}: {type(e_recv).__name__} - {e_recv}")
                    # import traceback
                    # traceback.print_exc()
                    await asyncio.sleep(1) # Small delay before trying to recv again
                    continue
        
        except websockets.InvalidURI:
            print(f"ERROR: Invalid WebSocket URI: {self.websocket_url}")
        except websockets.WebSocketException as e: 
            print(f"ERROR: WebSocket connection setup failed for session {self.session_id}: {e}")
        except ConnectionRefusedError:
            print(f"ERROR: Connection refused for WebSocket session {self.session_id}.")
        except asyncio.CancelledError:
            print(f"WebSocket connection attempt for session {self.session_id} was cancelled.")
        except Exception as e_outer:
            print(f"ERROR: Unexpected outer error in WebSocket listener for session {self.session_id}: {type(e_outer).__name__} - {e_outer}")
            import traceback 
            traceback.print_exc()
        finally:
            print(f"Initiating cleanup for WebSocket session {self.session_id}.")
            if PROCESSED_LOG_BATCH: 
                print("Flushing final log batch before listener stops...")
                await process_and_flush_batch()

            # Ensure _websocket_connection is not None AND is an instance that should have .closed
            if self._websocket_connection and hasattr(self._websocket_connection, 'closed'): 
                if not self._websocket_connection.closed: 
                    print(f"Closing WebSocket connection for session {self.session_id}...")
                    try:
                        await asyncio.wait_for(self._websocket_connection.close(code=1000, reason="Client shutdown"), timeout=5.0)
                        print(f"WebSocket connection {self.session_id} explicitly closed.")
                    except asyncio.TimeoutError:
                        print(f"Timeout while trying to close WebSocket connection {self.session_id}.")
                    except websockets.ConnectionClosed: 
                        print(f"WebSocket {self.session_id} was already closing or closed.")
                    except websockets.InvalidState:
                         print(f"WebSocket {self.session_id} in invalid state for close.")
                    except Exception as e_close:
                        print(f"Error during explicit WebSocket close for session {self.session_id}: {type(e_close).__name__} - {e_close}")
                else:
                    print(f"WebSocket connection {self.session_id} was already closed (checked by .closed).")
            elif self._websocket_connection:
                 print(f"WebSocket connection object for session {self.session_id} exists but lacks .closed attribute (type: {type(self._websocket_connection)}). Cannot check/close normally.")
            else:
                print(f"No active WebSocket connection object to close for session {self.session_id}.")
            
            print(f"WebSocket listener processing for session {self.session_id} fully stopped.")
            if self._log_file_handle:
                try:
                    print(f"Closing log file: {OUTPUT_LOG_FILE}")
                    self._log_file_handle.close()
                except Exception as e_file_close:
                    print(f"Error closing log file: {e_file_close}")
                finally:
                    self._log_file_handle = None

    async def start(self):
        if not self.shutdown_event.is_set():
            await self._connect_and_listen()

    async def graceful_stop(self): # This is more of an external signal, main shutdown is via shutdown_event
        print(f"Graceful stop called for session {self.session_id}.")
        # The shutdown_event will cause the loop in _connect_and_listen to terminate.
        # The finally block there will handle closing the connection.
        # This method could try to close directly if needed, but might conflict if called concurrently.
        if self._websocket_connection and not self._websocket_connection.closed:
            print(f"Attempting to close websocket connection {self.session_id} during graceful_stop.")
            try:
                await self._websocket_connection.close(code=1000, reason="Graceful stop initiated by method call")
            except Exception as e:
                print(f"Exception during graceful_stop's direct close attempt for {self.session_id}: {e}")