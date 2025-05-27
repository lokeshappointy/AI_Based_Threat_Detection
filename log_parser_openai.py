import openai
import json
import os
import re # For parsing the .tfvars file
from collections import Counter
from datetime import datetime, timedelta, timezone # For timestamping generated rules

# --- Configuration ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("Please set the OPENAI_API_KEY environment variable.")

openai.api_key = OPENAI_API_KEY
MODEL_NAME = "gpt-3.5-turbo-0125"

# --- OpenAI Function Definitions (from previous script) ---
tools_definition = [
    {
        "type": "function",
        "function": {
            "name": "extract_security_entities",
            "description": "Extracts and lists unique Source IPs, User-Agent strings, and ASN IDs from a batch of log entries. Focus on entities that might be involved in suspicious activities or require further security review.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ips": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "A list of unique source IP addresses found in the logs that are deemed relevant for security analysis."
                    },
                    "user_agents": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "A list of unique User-Agent strings found in the logs that are deemed relevant or suspicious."
                    },
                    "asn_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "A list of unique ASN (Autonomous System Number) IDs found in the logs associated with relevant IPs."
                    }
                },
                "required": ["source_ips", "user_agents", "asn_ids"]
            }
        }
    }
]

# --- Log Loading and OpenAI Interaction (from previous script) ---
def load_logs(log_file_path="cloudflare_logs.ndjson"):
    logs = []
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    print(f"Warning: Could not decode JSON from line: {line.strip()}")
        return logs
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return []

def preprocess_logs_for_openai(logs, max_entries_for_prompt=50):
    extracted_data = []
    for log in logs[:max_entries_for_prompt]:
        entry = {
            "ip": log.get("ClientIP"),
            "user_agent": log.get("ClientRequestUserAgent"),
            "asn": log.get("ClientASN"),
            "uri": log.get("ClientRequestURI"),
            "method": log.get("ClientRequestMethod"),
            "status": log.get("EdgeResponseStatus"),
            "firewall_action": log.get("FirewallMatchesActions", [])
        }
        if entry["ip"] and entry["user_agent"] and entry["asn"] is not None:
            extracted_data.append(entry)
    return json.dumps(extracted_data, indent=2)

def analyze_logs_with_openai(log_data_str):
    if not log_data_str or log_data_str == "[]":
        print("No valid log data to send to OpenAI.")
        return None
    try:
        print("\n--- Sending data to OpenAI for analysis ---")
        messages = [
            {"role": "system", "content": "You are a security analyst assistant. Your task is to analyze Cloudflare log entries and extract security-relevant entities like source IPs, user agents, and ASNs, especially those that might be involved in suspicious activities (e.g., repeated failed logins, SQLi attempts, unusual user agents, or IPs associated with multiple blocked actions). For each entity type, provide only a list of the raw entities themselves. Do not provide explanations for each item, just the list of strings or numbers."},
            {"role": "user", "content": f"Here is a batch of Cloudflare log entries. Please extract the relevant source IPs, user agents, and ASN IDs: \n\n{log_data_str}"}
        ]
        response = openai.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            tools=tools_definition,
            tool_choice={"type": "function", "function": {"name": "extract_security_entities"}}
        )
        message = response.choices[0].message
        if message.tool_calls:
            tool_call = message.tool_calls[0]
            if tool_call.function.name == "extract_security_entities":
                function_args = json.loads(tool_call.function.arguments)
                return function_args
            else:
                print(f"Error: OpenAI called an unexpected function: {tool_call.function.name}")
        else:
            print("Warning: OpenAI did not call the expected function. Content:")
            print(message.content)
        return None
    except openai.APIError as e:
        print(f"OpenAI API Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during OpenAI call: {e}")
    return None

# --- NEW FUNCTIONS for WAF Rule Generation and .tfvars file update ---

def create_waf_rule_object(entity_type, entity_value, target_host="waf-test.appointy.ai"):
    """Creates a Python dictionary representing a WAF rule object."""
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    description = f"AI Generated: Block {entity_type} '{entity_value}' on {target_host} at {current_time}"
    expression = ""

    if entity_type == "IP":
        # Ensure IP is not quoted for 'eq'
        expression = f"(http.host eq \"{target_host}\") and (ip.src eq {entity_value})"
    elif entity_type == "User-Agent":
        # Escape special characters in user agent for HCL string and Cloudflare expression
        escaped_entity_value = json.dumps(entity_value)[1:-1] # Basic escaping for string literal
        expression = f"(http.host eq \"{target_host}\") and (http.user_agent contains \"{escaped_entity_value}\")"
    elif entity_type == "ASN":
         # ASNs are numbers, not quoted
        expression = f"(http.host eq \"{target_host}\") and (ip.geoip.asnum eq {entity_value})"
    else:
        return None

    return {
        "action": "block",  # Or "challenge" - make this configurable later
        "description": description,
        "enabled": True,
        "expression": expression,
        "action_parameters": None,
        "logging": None  # Logging only allowed for "skip" actions
    }

def hcl_format_rule(rule_dict):
    """ Formats a Python rule dictionary into an HCL-like string for .tfvars """
    # Basic HCL formatting. For complex cases, a proper HCL library is better.
    # This handles simple structures and assumes no complex nested HEREDOCs inside expressions for now.
    lines = ["  {"]
    for key, value in rule_dict.items():
        if value is None:
            val_str = "null"
        elif isinstance(value, bool):
            val_str = "true" if value else "false"
        elif isinstance(value, (int, float)):
            val_str = str(value)
        elif key == "expression" and "\n" in value: # Handle multi-line expressions (HEREDOC)
            # Ensure HEREDOC content is indented correctly relative to the assignment
            indented_expression = "\n".join(["      " + line for line in value.splitlines()])
            val_str = f"<<EOT\n{indented_expression}\n    EOT" # Assumes 4 spaces for EOT marker
        else: # Strings
            # Basic escaping for HCL strings: escape backslashes and double quotes
            escaped_value = value.replace("\\", "\\\\").replace("\"", "\\\"")
            val_str = f"\"{escaped_value}\""
        lines.append(f"    {key} = {val_str}")
    lines.append("  },")
    return "\n".join(lines)


def update_tfvars_file(tfvars_path, new_rules):
    """
    Reads a .tfvars file, appends new WAF rules to the waf_rules list,
    and writes the content back. This is a simplified parser.
    """
    try:
        with open(tfvars_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: .tfvars file not found at {tfvars_path}")
        return

    # Find the waf_rules list assignment
    # This regex is basic and assumes waf_rules = [ ... ] structure.
    # It captures the content inside the brackets.
    match = re.search(r"baseline_waf_rules\s*=\s*\[(.*?)\]", content, re.DOTALL | re.MULTILINE)
    # Or try with waf_rules if that's the name in tfvars
    if not match:
        match = re.search(r"waf_rules\s*=\s*\[(.*?)\]", content, re.DOTALL | re.MULTILINE)


    if not match:
        print(f"Error: Could not find 'waf_rules = [' or 'baseline_waf_rules = [' list in {tfvars_path}")
        print("Make sure the variable is named correctly and assigned a list.")
        return

    existing_rules_str = match.group(1).strip()
    start_index = match.start()
    end_index = match.end()
    
    # --- Extract existing rule descriptions to avoid duplicates ---
    existing_descriptions = set()
    # This regex is to find "description = "..." lines within existing rule blocks
    # It's a simplification; a full HCL parser would be more robust.
    for desc_match in re.finditer(r'description\s*=\s*"(.*?)"', existing_rules_str):
        existing_descriptions.add(desc_match.group(1))

    # --- Filter new rules to add (avoiding duplicates by description) ---
    rules_to_add_hcl = []
    added_count = 0
    for rule in new_rules:
        if rule["description"] not in existing_descriptions:
            rules_to_add_hcl.append(hcl_format_rule(rule)) # Format new rule to HCL string
            existing_descriptions.add(rule["description"]) # Add to set to prevent adding it again in this run
            added_count += 1
        else:
            print(f"Skipping duplicate rule (based on description): {rule['description']}")
            
    if not rules_to_add_hcl:
        print("No new unique rules to add.")
        return

    print(f"Adding {added_count} new unique rules to {tfvars_path}")

    # --- Construct the new waf_rules list content ---
    new_rules_hcl_str = "\n".join(rules_to_add_hcl)
    
    # Add a comma if existing rules string is not empty and doesn't end with a comma
    if existing_rules_str and not existing_rules_str.endswith(","):
        existing_rules_str += ","

    if existing_rules_str: # If there were existing rules, add new ones after a newline and comma
        updated_rules_content = f"{existing_rules_str}\n{new_rules_hcl_str}"
    else: # If the list was empty, just add the new rules
        updated_rules_content = new_rules_hcl_str.rstrip(',') # Remove trailing comma if it's the only content

    # --- Reconstruct the entire file content ---
    # Determine the variable name used (waf_rules or baseline_waf_rules)
    var_name_used = "waf_rules" if "waf_rules" in match.group(0) else "baseline_waf_rules"

    new_content = (
        content[:start_index] + # Content before waf_rules list
        f"{var_name_used} = [\n{updated_rules_content}\n]" + # New waf_rules list
        content[end_index:] # Content after waf_rules list
    )

    try:
        with open(tfvars_path, 'w') as f:
            f.write(new_content)
        print(f"Successfully updated {tfvars_path}")
    except Exception as e:
        print(f"Error writing to {tfvars_path}: {e}")


def main():
    log_entries = load_logs()
    if not log_entries:
        return

    print(f"Loaded {len(log_entries)} log entries.")
    
    # --- Local Aggregation (as before) ---
    print("\n--- Local Preliminary Aggregation ---")
    local_ips = Counter(log["ClientIP"] for log in log_entries if log.get("ClientIP"))
    local_uas = Counter(log["ClientRequestUserAgent"] for log in log_entries if log.get("ClientRequestUserAgent"))
    local_asns = Counter(log["ClientASN"] for log in log_entries if log.get("ClientASN") is not None)
    print("Top 5 IPs (Local):", local_ips.most_common(5))
    print("Top 5 User Agents (Local):", local_uas.most_common(5))
    print("Top 5 ASNs (Local):", local_asns.most_common(5))


    openai_input_data_str = preprocess_logs_for_openai(log_entries, max_entries_for_prompt=30) # Reduced for testing

    if openai_input_data_str and openai_input_data_str != "[]":
        extracted_entities = analyze_logs_with_openai(openai_input_data_str)

        if extracted_entities:
            print("\n--- Final Extracted Entities from OpenAI ---")
            print("Source IPs:", extracted_entities.get("source_ips", []))
            print("User Agents:", extracted_entities.get("user_agents", []))
            print("ASN IDs:", extracted_entities.get("asn_ids", []))

            # --- Generate WAF rule objects from OpenAI entities ---
            ai_generated_rules = []
            # Simple logic: block all IPs and User-Agents identified by OpenAI for waf-test.appointy.ai
            # In a real scenario, you'd have more sophisticated decision logic here.
            target_host_for_ai_rules = "waf-test.appointy.ai" # Make this configurable

            for ip in extracted_entities.get("source_ips", []):
                # Add additional checks here, e.g., IP reputation, frequency, etc.
                # For now, let's assume OpenAI's selection is good enough for a rule
                if ip: # Ensure IP is not None or empty
                    rule_obj = create_waf_rule_object("IP", ip, target_host_for_ai_rules)
                    if rule_obj:
                        ai_generated_rules.append(rule_obj)
            
            for ua in extracted_entities.get("user_agents", []):
                if ua: # Ensure UA is not None or empty
                    rule_obj = create_waf_rule_object("User-Agent", ua, target_host_for_ai_rules)
                    if rule_obj:
                        ai_generated_rules.append(rule_obj)
            
            # Optionally, handle ASNs - blocking entire ASNs is risky, maybe 'challenge'
            # for asn_id in extracted_entities.get("asn_ids", []):
            #     if asn_id:
            #         rule_obj = create_waf_rule_object("ASN", asn_id, target_host_for_ai_rules)
            #         # if rule_obj:
            #         #     rule_obj["action"] = "challenge" # Example: Challenge ASNs
            #         #     ai_generated_rules.append(rule_obj)


            if ai_generated_rules:
                print(f"\n--- AI Generated {len(ai_generated_rules)} WAF rule objects (before filtering duplicates) ---")
                # for r in ai_generated_rules:
                #     print(json.dumps(r, indent=2))

                # --- Update the .tfvars file ---
                # Path relative to where this script is run.
                # Your script is in AI_Based_Threat_Detection, tfvars is in cloudflare/zones/appointy_ai/
                # Adjust path as necessary. For this example, assume script is run from project root
                # or you provide the full path.
                tfvars_file_path = "cloudflare/zones/appointy_ai/appointy_ai.tfvars"
                # For testing, you might want to copy appointy_ai.tfvars to a temp file first
                # import shutil
                # shutil.copy(tfvars_file_path, "temp_appointy_ai.tfvars")
                # update_tfvars_file("temp_appointy_ai.tfvars", ai_generated_rules)

                update_tfvars_file(tfvars_file_path, ai_generated_rules)
            else:
                print("No WAF rules generated based on OpenAI output.")

        else:
            print("Could not extract entities using OpenAI.")
    else:
        print("No suitable log data was prepared for OpenAI analysis.")

if __name__ == "__main__":
    main()