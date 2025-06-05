# main_logger.py
import asyncio
import signal
import os
# Assuming cloudflare_client and websocket_handler are in the same directory
from cloudflare_client import CloudflareLogSessionManager
from websocket_handler import WebSocketLogReceiver # Ensure this file exists/is updated
from log_processor import LogProcessor # Import the new processor
from config import WEBSOCKET_ERROR_RETRY_DELAY_SECONDS

running_tasks = []
shutdown_event = asyncio.Event()
log_processor = None # Global instance of the log processor

def signal_handler(signum, frame):
    print(f"\\nSignal {signal.Signals(signum).name} received, initiating graceful shutdown...")
    # Set the main shutdown event
    shutdown_event.set()
    # Signal the log processor to start its shutdown sequence
    if log_processor:
        # Run stop() in a separate task since signal handlers shouldn't be async directly
        asyncio.create_task(log_processor.stop())


async def run_log_pipeline():
    cf_manager = CloudflareLogSessionManager()
    global log_processor # Use the global processor instance
    log_processor = LogProcessor() # Create the processor instance

    ws_receiver_task = None # Keep track of the current receiver task

    print("Starting log processor...")
    log_processor.start() # Start the background processing task


    try:
        while not shutdown_event.is_set():
            print("Attempting to create new Cloudflare Instant Logs session...")
            websocket_url, session_id = await cf_manager.create_instant_log_session()

            if websocket_url and not shutdown_event.is_set():
                print(f"Obtained WebSocket URL for session {session_id}")
                # Pass the log_processor instance to the WebSocket handler
                current_ws_receiver = WebSocketLogReceiver(websocket_url, session_id, shutdown_event, log_processor)

                print(f"Starting WebSocket receiver task for session {session_id}...")
                ws_receiver_task = asyncio.create_task(current_ws_receiver.start())
                running_tasks.append(ws_receiver_task) # Add to global list for shutdown

                try:
                    # Wait for the receiver task to finish (either by disconnection or error)
                    await ws_receiver_task
                except asyncio.CancelledError:
                    print(f"Main loop: WebSocket receiver task for session {session_id} was cancelled.")
                    # If cancelled from outside (e.g. global shutdown), the main loop condition will handle breaking
                except Exception as e_task:
                    print(f"Main loop: WebSocket receiver task for {session_id} ended with error: {e_task}")
                finally:
                    # Clean up the finished receiver task
                    if ws_receiver_task in running_tasks:
                        running_tasks.remove(ws_receiver_task)
                    # Ensure the receiver's stop method is called if it didn't exit cleanly itself
                    await current_ws_receiver.stop()

                # Check shutdown status after the receiver task finishes
                if shutdown_event.is_set():
                    print("Main loop: Shutdown event detected after session handling. Exiting.")
                    break

                print(f"Main loop: Session {session_id} concluded or failed. Preparing to create a new session after a delay...")
                # Wait before attempting to create a new session
                await asyncio.sleep(WEBSOCKET_ERROR_RETRY_DELAY_SECONDS)

            elif shutdown_event.is_set():
                print("Main loop: Shutdown requested during session creation attempt.")
                break
            else:
                # create_instant_log_session should handle retries, so this else might be rare,
                # but a small delay ensures we don't hammer the API if something goes wrong.
                print("Main loop: Failed to obtain WebSocket URL. Retrying...")
                await asyncio.sleep(5)

    finally:
        print("Main loop: Initiating final cleanup.")
        # Signal processor to stop and wait for it
        if log_processor:
            await log_processor.stop() # Ensure processor stops gracefully
            log_processor = None # Clear reference

        # Close the aiohttp session managed by CloudflareLogSessionManager
        await cf_manager.close_aiohttp_session()

        print("Main log pipeline loop has finished.")


async def initiate_shutdown(signal_obj):
    """Sets the shutdown event and gives tasks a moment to react."""
    print(f"Received exit signal {signal_obj.name if hasattr(signal_obj, 'name') else signal_obj}...")
    if not shutdown_event.is_set():
        print("Signalling all components to shut down via event.")
        shutdown_event.set()
        # Signal the log processor to start its shutdown sequence
        if log_processor:
            # Await the log processor's stop method directly here as we are in an async context
            await log_processor.stop()
    else:
        print("Shutdown already in progress.")

    # Give running tasks a brief moment to acknowledge the shutdown event
    await asyncio.sleep(0.1)

    # Cancel any tasks that haven't finished gracefully
    tasks_to_cancel = [t for t in running_tasks if not t.done()]
    current_task = asyncio.current_task() # Avoid cancelling self

    if tasks_to_cancel:
        print(f"Cancelling {len(tasks_to_cancel)} outstanding tasks...")
        for task in tasks_to_cancel:
            if task and task is not current_task: # Ensure task is not None and not the current task
                 task.cancel()
        # Wait for tasks to be cancelled, ignoring CancelledError
        await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
        print("Gathered results from cancelled tasks.")
    else:
        print("No outstanding tasks to cancel.")


if __name__ == "__main__":
    if not os.getenv("CLOUDFLARE_API_TOKEN") or not os.getenv("CLOUDFLARE_ZONE_ID"):
         print("ERROR: CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID environment variables not set.")
         print("Please configure these in a .env file or your environment.")
    else:
        # Set up signal handlers before running the main async function
        # Use loop.add_signal_handler for setting handlers in async context
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
             # Use a partial to pass the signal object to the handler
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(initiate_shutdown(s)))

        print("Starting Cloudflare Instant Log streaming pipeline... Press Ctrl+C to stop.")
        try:
            # asyncio.run manages the event loop and handles basic cleanup
            asyncio.run(run_log_pipeline()) # Call run_log_pipeline directly
        except KeyboardInterrupt:
            print("\\nKeyboardInterrupt detected. Shutdown should be handled by signal handler.")
            # The signal handler should have already initiated shutdown_event.set()
            # Just ensure the main loop has a chance to exit.
        finally:
            print("Exiting main application block.")
