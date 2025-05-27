import json

input_json_file = 'cloudflare_logs.json' # Assuming your current file is a valid JSON array
output_ndjson_file = 'cloudflare_logs.ndjson'

try:
    with open(input_json_file, 'r') as infile:
        data_array = json.load(infile) # Load the entire JSON array

    with open(output_ndjson_file, 'w') as outfile:
        for item in data_array:
            # Write each item as a JSON string on its own line
            outfile.write(json.dumps(item) + '\n')
    
    print(f"Successfully converted '{input_json_file}' to NDJSON format in '{output_ndjson_file}'")

except FileNotFoundError:
    print(f"Error: Input file '{input_json_file}' not found.")
except json.JSONDecodeError:
    print(f"Error: Could not decode JSON from '{input_json_file}'. Is it a valid JSON array?")
except Exception as e:
    print(f"An unexpected error occurred: {e}")