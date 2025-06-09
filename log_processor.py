# log_processor.py
import asyncio
import time
import json
from gemini_client import GeminiClient
from config import MAX_LOG_BATCH_SIZE, BATCH_FLUSH_INTERVAL_SECONDS, OUTPUT_LOG_FILE # Import OUTPUT_LOG_FILE

class LogProcessor:
    def __init__(self):
        self.gemini_client = GeminiClient()
        self._log_buffer = []
        self._last_flush_time = time.time()
        self._processing_task = None # To hold the background task
        self._shutdown_event = asyncio.Event() # Use a separate event for processor shutdown

        # Open the output file for appending received raw logs
        # Ensure the directory exists if using subdirectories
        try:
            if OUTPUT_LOG_FILE:
                 # Use 'a' mode for append, 'w' would overwrite
                self._output_file = open(OUTPUT_LOG_FILE, 'a')
            else:
                self._output_file = None
        except IOError as e:
            print(f"Error opening output log file {OUTPUT_LOG_FILE}: {e}")
            self._output_file = None

    def add_log_entry(self, log_entry: dict):
        """Adds a parsed log entry to the buffer."""
        self._log_buffer.append(log_entry)
        # Optionally write raw log line to file
        if self._output_file:
            try:
                # Assuming log_entry is already a dictionary parsed from JSON line
                # Convert back to JSON string for NDJSON file format
                self._output_file.write(json.dumps(log_entry) + '\n')
                self._output_file.flush() # Ensure it's written immediately
            except Exception as e:
                print(f"Error writing log entry to file: {e}")

    async def process_buffer(self):
        """Processes the buffer, sending batches to Gemini."""
        if not self._log_buffer:
            return

        print(f"Processing buffer: {len(self._log_buffer)} entries.")
        # Take a batch and clear the buffer immediately
        batch_to_process = self._log_buffer[:]
        self._log_buffer = []
        self._last_flush_time = time.time()

        # Analyze the batch
        threats = await self.gemini_client.analyze_logs(batch_to_process)

        if threats:
            print(f"--- Detected Threats ({len(threats)}) ---")
            for threat in threats:
                print(f"  Entity Type: {threat.get('entity_type', 'N/A')}")
                print(f"  Entity Value: {threat.get('entity_value', 'N/A')}")
                print(f"  Reason: {threat.get('reason', 'N/A')}")
                print(f"  Suggested Action: {threat.get('suggested_action', 'N/A')}")
                print(f"  Confidence Score: {threat.get('confidence_score', 'N/A')}")
                print("-" * 10) # Separator for threats
        else:
            print("Batch processed. No threats reported by AI.")

    async def _background_processor(self):
        """Background task to periodically check and process the buffer."""
        print("Log processor background task started.")
        while not self._shutdown_event.is_set():
            await asyncio.sleep(1) # Check buffer every second

            # Process if buffer is full or timeout reached
            if len(self._log_buffer) >= MAX_LOG_BATCH_SIZE or \
               (time.time() - self._last_flush_time >= BATCH_FLUSH_INTERVAL_SECONDS and self._log_buffer):
                await self.process_buffer()
        print("Log processor background task shutting down.")


    def start(self):
        """Starts the background processing task."""
        if self._processing_task is None or self._processing_task.done():
            print("Starting Log Processor background task.")
            self._processing_task = asyncio.create_task(self._background_processor())
        else:
            print("Log Processor background task already running.")


    async def stop(self):
        """Signals the background task to stop and processes any remaining logs."""
        print("Initiating Log Processor shutdown.")
        self._shutdown_event.set() # Signal shutdown to the background task

        # Wait for the background task to finish its current checks and exit loop
        if self._processing_task and not self._processing_task.done():
             print("Waiting for log processor background task to finish...")
             try:
                 await asyncio.wait_for(self._processing_task, timeout=5.0) # Wait a bit
             except asyncio.TimeoutError:
                 print("Log processor background task did not finish in time, cancelling.")
                 self._processing_task.cancel()
                 try:
                     await self._processing_task
                 except asyncio.CancelledError:
                     pass # Expected

        # Process any remaining logs in the buffer before exiting
        if self._log_buffer:
            print(f"Processing {len(self._log_buffer)} remaining logs before final shutdown.")
            await self.process_buffer()

        # Close the output file if it was opened
        if self._output_file:
            print(f"Closing output log file: {OUTPUT_LOG_FILE}")
            self._output_file.close()
            self._output_file = None # Clear reference
