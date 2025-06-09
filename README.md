# waf-agent

This project implements an AI-based threat detection system that leverages Cloudflare's real-time logging capabilities and Google's Gemini AI to identify and report suspicious activity in your web traffic. By analyzing log data, the system can detect a variety of threats, including SQL injection, XSS, dictionary attacks, and anomalous request patterns, providing an additional layer of security for your applications.

## Features

- **Real-time Threat Analysis**: Ingests Cloudflare's Instant Logs to monitor traffic as it happens.
- **AI-Powered Detection**: Uses Google's Gemini AI to analyze log data for a wide range of threats.
- **Rate Limit Monitoring**: Identifies suspicious spikes in request rates from individual IPs.
- **Customizable Log Fields**: Allows you to specify which log fields to analyze for more targeted threat detection.
- **Actionable Threat Reports**: Generates clear and concise threat reports with suggested actions (e.g., `block`, `challenge`).
- **Flexible Configuration**: Easily configured through environment variables and a central `config.py` file.
- **Extensible**: Designed to be easily extended with new detection logic and integrations.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.8+
- A Cloudflare account with a configured zone
- A Google AI API key for Gemini

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/waf-agent.git
   cd waf-agent
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up your environment variables:**
   You can set up your environment variables in one of two ways:

   **Option 1: Using a `.env` file**
   Create a `.env` file in the project root and add the following variables:
   ```
   CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
   CLOUDFLARE_ZONE_ID="your_cloudflare_zone_id"
   GEMINI_API_KEY="your_gemini_api_key"
   ```

   **Option 2: Using the `export` command**
   Alternatively, you can export the variables directly in your terminal:
   ```bash
   export CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
   export CLOUDFLARE_ZONE_ID="your_cloudflare_zone_id"
   export GEMINI_API_KEY="your_gemini_api_key"
   ```

### Configuration

The primary configuration file is `config.py`. You can adjust the following settings to customize the behavior of the application:

- `GEMINI_MODEL_NAME`: The Gemini model to use for analysis (e.g., `gemini-1.5-pro-latest`).
- `LOG_FIELDS_LIST`: The list of Cloudflare log fields to include in the analysis.
- `MAX_LOG_BATCH_SIZE`: The number of log entries to batch together for AI analysis.
- `BATCH_FLUSH_INTERVAL_SECONDS`: The time interval at which to process log batches.
- `OUTPUT_LOG_FILE`: The file where raw Cloudflare logs will be stored.

### Running the Application

To start the threat detection system, run the following command:

```bash
python main_logger.py
```

The application will begin streaming logs from Cloudflare, analyzing them for threats, and printing any findings to the console.

## Project Structure

```
.
├── cloudflare/              # Terraform configuration for Cloudflare resources
├── .env                     # Environment variables (not committed)
├── .gitignore               # Git ignore file
├── README.md                # This file
├── cloudflare_client.py     # Handles communication with the Cloudflare API
├── config.py                # Application configuration
├── gemini_client.py         # Handles communication with the Gemini AI API
├── log_processor.py         # Processes and analyzes log batches
├── main_logger.py           # Main application entry point
├── requirements.txt         # Python dependencies
└── websocket_handler.py     # Handles the WebSocket connection for log streaming
```

## How It Works

1. **Log Streaming**: The application establishes a WebSocket connection to Cloudflare's Instant Logs endpoint to receive real-time log data.
2. **Log Batching**: Logs are collected into batches based on size and time intervals defined in `config.py`.
3. **AI Analysis**: Each batch of logs is sent to the Gemini AI with a prompt that asks it to identify suspicious activity.
4. **Threat Reporting**: If the AI identifies any threats, it returns a structured report with details about the suspicious entity, the reason for flagging, a suggested action, and a confidence score.
5. **Console Output**: The application prints the threat reports to the console, providing you with real-time insights into potential attacks.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you have any suggestions or find any bugs.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
