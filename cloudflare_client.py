# cloudflare_client.py
import aiohttp # New import
import asyncio # New import
import json
import time # Still used for sleep
from config import (
    CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID,
    LOG_FIELDS, LOG_FILTER_JSON_STRING, LOG_SAMPLE_RATE,
    RETRY_DELAY_SECONDS
)

CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"

class CloudflareLogSessionManager:
    def __init__(self):
        if not CLOUDFLARE_API_TOKEN or not CLOUDFLARE_ZONE_ID:
            raise ValueError("Cloudflare API Token or Zone ID not configured.")
        
        self.headers = {
            "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json"
        }
        self.zone_id = CLOUDFLARE_ZONE_ID
        self._session = None # For aiohttp ClientSession

    async def _get_aiohttp_session(self):
        """Creates or returns an existing aiohttp ClientSession."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(headers=self.headers)
        return self._session

    async def close_aiohttp_session(self):
        """Closes the aiohttp ClientSession."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
            print("aiohttp session closed.")

    async def create_instant_log_session(self): # Now an async method
        """
        Creates a new Cloudflare Instant Logs job and returns the WebSocket URL.
        Retries on failure. Uses aiohttp for async requests.
        """
        url = f"{CLOUDFLARE_API_BASE_URL}/zones/{self.zone_id}/logpush/edge/jobs"
        payload = {
            "fields": LOG_FIELDS,
            "sample": LOG_SAMPLE_RATE,
            "filter": LOG_FILTER_JSON_STRING,
            "kind": "instant-logs"
        }
        
        session = await self._get_aiohttp_session()

        while True: 
            print("Attempting to create new Cloudflare Instant Logs session (async)...")
            try:
                async with session.post(url, json=payload, timeout=30) as response:
                    response_text = await response.text() # Get text for debugging if json fails
                    response.raise_for_status() 
                    data = await response.json()

                if data.get("success") and data.get("result", {}).get("destination_conf"):
                    ws_url = data["result"]["destination_conf"]
                    job_id = data["result"].get("id", "N/A")
                    session_id_from_url = ws_url.split('/')[-1]
                    print(f"Successfully created Instant Logs job. Session ID: {session_id_from_url} (Job ID: {job_id})")
                    print(f"WebSocket URL: {ws_url}")
                    return ws_url, session_id_from_url
                else:
                    error_messages = data.get('errors', [{'message': 'Unknown error from Cloudflare API.'}])
                    print(f"Error creating Instant Logs session: {error_messages}")
                    if any(err.get("code") == 1303 for err in error_messages if isinstance(err, dict)):
                        print("An Instant Log session is already active for this zone. Waiting before retry...")

            except aiohttp.ClientResponseError as e: # Specific error for bad status codes
                print(f"HTTPError (aiohttp) when creating Instant Logs session: {e.status} - {e.message} - Response: {response_text if 'response_text' in locals() else 'N/A'}")
            except aiohttp.ClientError as e: # Catches other client errors like connection issues
                print(f"ClientError (aiohttp) when creating Instant Logs session: {e}")
            except asyncio.TimeoutError:
                print(f"Timeout when creating Instant Logs session with aiohttp.")
            except json.JSONDecodeError as e:
                 print(f"Failed to decode JSON response from Cloudflare API: {e}. Response text: {response_text if 'response_text' in locals() else 'N/A'}")
            except Exception as e:
                print(f"An unexpected error occurred in create_instant_log_session (async): {e}")
            
            print(f"Retrying session creation in {RETRY_DELAY_SECONDS} seconds...")
            await asyncio.sleep(RETRY_DELAY_SECONDS) # Use asyncio.sleep