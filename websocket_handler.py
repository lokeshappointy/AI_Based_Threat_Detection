# websocket_handler.py
import asyncio
import aiohttp
import json
from config import WEBSOCKET_ERROR_RETRY_DELAY_SECONDS # Import delay from config

class WebSocketLogReceiver:
    def __init__(self, websocket_url: str, session_id: str, shutdown_event: asyncio.Event, log_processor):
        self._websocket_url = websocket_url
        self._session_id = session_id
        self._shutdown_event = shutdown_event
        self._log_processor = log_processor # Reference to the log processor
        self._ws = None # To hold the aiohttp websocket connection

    async def start(self):
        """Connects to the WebSocket and receives logs."""
        print(f"WebSocketLogReceiver for session {self._session_id} starting connection to {self._websocket_url}")

        # Use a ClientSession provided externally or create one if necessary
        # For this integration, it's better to let main manage the aiohttp session
        # but for simplicity here, we'll create one within the class for the websocket connection itself.
        # A more robust design might pass the session from CloudflareLogSessionManager.
        async with aiohttp.ClientSession() as session:
            while not self._shutdown_event.is_set():
                try:
                    print(f"Attempting WebSocket connection to {self._websocket_url}")
                    # Use a context manager for the websocket connection
                    async with session.ws_connect(self._websocket_url) as ws:
                        self._ws = ws # Store reference to the active connection
                        print(f"WebSocket connected successfully for session {self._session_id}")

                        # Keep receiving messages until disconnected or shutdown
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                try:
                                    # Each message is a newline-delimited JSON object (NDJSON)
                                    # Split by newline to handle potential multiple logs in one message,
                                    # though typically it's one log per message.
                                    log_lines = msg.data.strip().split('\\n')
                                    for line in log_lines:
                                        if line: # Ensure line is not empty
                                            log_entry = json.loads(line)
                                            # Pass the parsed log entry to the processor
                                            self._log_processor.add_log_entry(log_entry)

                                except json.JSONDecodeError as e:
                                    print(f"Error decoding log message JSON: {e} - Data: {msg.data[:200]}...")
                                except Exception as e:
                                    print(f"Error processing received log message: {e}")

                            elif msg.type == aiohttp.WSMsgType.ERROR:
                                print(f"WebSocket Error received: {msg.data}")
                                break # Break loop to attempt reconnection
                            elif msg.type == aiohttp.WSMsgType.CLOSED:
                                print(f"WebSocket connection closed with code {ws.close_code}: {ws.close_message}")
                                break # Break loop to attempt reconnection

                        # If we break out of the async for loop, the connection is closed
                        print(f"WebSocket connection for session {self._session_id} closed. Attempting to re-establish or waiting for new session.")

                except aiohttp.ClientConnectorError as e:
                    print(f"WebSocket connection failed: {e}. Retrying in {WEBSOCKET_ERROR_RETRY_DELAY_SECONDS} seconds.")
                    # Connection error, wait and the outer loop will attempt to reconnect

                except Exception as e:
                    print(f"An unexpected error occurred in WebSocketLogReceiver: {e}")
                    # Catch other exceptions, wait and retry

                # If shutdown is requested while waiting or during error
                if self._shutdown_event.is_set():
                    print("Shutdown event detected in WebSocket receiver.")
                    break

                # Wait before attempting reconnection or requesting a new session
                print(f"Waiting {WEBSOCKET_ERROR_RETRY_DELAY_SECONDS} seconds before attempting reconnect/new session...")
                await asyncio.sleep(WEBSOCKET_ERROR_RETRY_DELAY_SECONDS)

        print(f"WebSocketLogReceiver for session {self._session_id} shutting down.")
        # The aiohttp ClientSession context manager will close the session on exit


    async def stop(self):
        """Gracefully closes the WebSocket connection."""
        print(f"Stopping WebSocketLogReceiver for session {self._session_id}.")
        if self._ws and not self._ws.closed:
            await self._ws.close()
            print(f"WebSocket connection for session {self._session_id} closed gracefully.")
