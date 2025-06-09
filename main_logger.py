# main_logger.py
import asyncio
import signal
import os
from cloudflare_client import CloudflareLogSessionManager
from websocket_handler import WebSocketLogReceiver
from log_processor import LogProcessor
from config import WEBSOCKET_ERROR_RETRY_DELAY_SECONDS

# Global shutdown event and reference to the log processor
shutdown_event = asyncio.Event()
_log_processor_instance = None
_cf_manager_instance = None
_main_tasks = set()

async def _handle_shutdown_signal(sig, loop):
    """Handles shutdown signals like SIGINT (Ctrl+C) and SIGTERM."""
    if shutdown_event.is_set():
        print("Shutdown already in progress. Press Ctrl+C again to force exit if stuck.")
        # Optionally, add a counter for multiple Ctrl+C to force exit sooner
        # For now, subsequent Ctrl+C will likely re-trigger this or KeyboardInterrupt
        return

    print(f"Signal {sig.name} received. Initiating graceful shutdown...")
    shutdown_event.set()

    # 1. Stop the log processor (which processes remaining logs)
    if _log_processor_instance:
        print("Stopping log processor...")
        await _log_processor_instance.stop()
        print("Log processor stopped.")

    # 2. Cancel main operational tasks (like run_log_pipeline and websocket receivers)
    # Tasks should respond to shutdown_event or CancelledError
    current_task = asyncio.current_task()
    tasks_to_cancel = [task for task in _main_tasks if task is not current_task and not task.done()]

    if tasks_to_cancel:
        print(f"Cancelling {len(tasks_to_cancel)} main tasks...")
        for task in tasks_to_cancel:
            task.cancel()
        # Wait for them to complete cancellation
        await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
        print("Main tasks cancellation complete.")

    # 3. Close Cloudflare session manager (aiohttp session)
    # This is typically done in run_log_pipeline's finally, but good to ensure if shutdown is abrupt
    if _cf_manager_instance:
        print("Closing Cloudflare session manager...")
        await _cf_manager_instance.close_aiohttp_session()
        print("Cloudflare session manager closed.")
    
    print("Graceful shutdown sequence complete.")
    # Optional: Stop the loop if it doesn't stop automatically after tasks are done
    # all_tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    # if not all_tasks:
    #    loop.stop()


async def run_log_pipeline():
    global _log_processor_instance, _cf_manager_instance
    
    _cf_manager_instance = CloudflareLogSessionManager()
    _log_processor_instance = LogProcessor()

    print("Starting log processor background task...")
    _log_processor_instance.start() # Starts its own asyncio task

    current_ws_receiver_task = None

    try:
        while not shutdown_event.is_set():
            print("Attempting to create new Cloudflare Instant Logs session...")
            websocket_url, session_id = await _cf_manager_instance.create_instant_log_session()

            if shutdown_event.is_set(): # Check after potentially long call
                print("Shutdown detected during session creation. Exiting pipeline.")
                break

            if websocket_url:
                print(f"Obtained WebSocket URL for session {session_id}")
                current_ws_receiver = WebSocketLogReceiver(websocket_url, session_id, shutdown_event, _log_processor_instance)
                
                print(f"Starting WebSocket receiver task for session {session_id}...")
                current_ws_receiver_task = asyncio.create_task(current_ws_receiver.start())
                _main_tasks.add(current_ws_receiver_task)
                
                try:
                    await current_ws_receiver_task
                except asyncio.CancelledError:
                    print(f"WebSocket receiver task for session {session_id} was cancelled.")
                except Exception as e_task:
                    print(f"WebSocket receiver task for {session_id} ended with error: {e_task}")
                finally:
                    _main_tasks.discard(current_ws_receiver_task)
                    print(f"WebSocket receiver task for session {session_id} finished. Cleaning up receiver.")
                    await current_ws_receiver.stop() # Ensure WebSocket is closed if not already
                
                if shutdown_event.is_set():
                    print("Shutdown event detected after WebSocket session. Exiting pipeline.")
                    break
                
                print(f"Session {session_id} concluded. Will attempt new session after delay if not shutting down.")
                # Delay before trying to get a new session, allowing shutdown to interrupt
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=WEBSOCKET_ERROR_RETRY_DELAY_SECONDS)
                    if shutdown_event.is_set():
                        print("Shutdown detected during delay. Exiting pipeline.")
                        break
                except asyncio.TimeoutError:
                    pass # Timeout means delay passed, continue to new session
            
            else: # Failed to get websocket_url
                if shutdown_event.is_set():
                    print("Shutdown detected after failing to get WebSocket URL. Exiting pipeline.")
                    break
                print(f"Failed to obtain WebSocket URL. Retrying after {RETRY_DELAY_SECONDS} seconds (from cf_client)...")
                # create_instant_log_session has its own retry, but if it returns None quickly, add a small delay here too.
                # This is usually handled by create_instant_log_session's internal retry delays.
                # A short sleep here if create_instant_log_session returns None immediately after many retries.
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=5) # Shorter delay, cf_manager has main retry
                    if shutdown_event.is_set(): break
                except asyncio.TimeoutError:
                    pass


    except asyncio.CancelledError:
        print("Main log pipeline (run_log_pipeline) was cancelled.")
    finally:
        print("Main log pipeline: Initiating final cleanup...")
        
        # Stop log processor if not already stopped (e.g. if pipeline cancelled before signal handler ran fully)
        if _log_processor_instance and not _log_processor_instance._shutdown_event.is_set():
            print("Pipeline cleanup: Ensuring log processor is stopped.")
            await _log_processor_instance.stop()

        # Close Cloudflare session manager
        if _cf_manager_instance:
            print("Pipeline cleanup: Closing Cloudflare session manager.")
            await _cf_manager_instance.close_aiohttp_session()
        
        print("Main log pipeline has finished.")


async def main_async_wrapper():
    """Wrapper to set up signal handlers and run the main application logic."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig, l=loop: asyncio.create_task(_handle_shutdown_signal(s, l)))

    pipeline_task = asyncio.create_task(run_log_pipeline())
    _main_tasks.add(pipeline_task)
    
    try:
        await pipeline_task # Wait for the main pipeline to complete or be cancelled
    except asyncio.CancelledError:
        print("Main application wrapper: run_log_pipeline task was cancelled.")
    finally:
        _main_tasks.discard(pipeline_task)
        # Ensure shutdown_event is set if the pipeline task ends for any reason other than a signal
        # This helps ensure other components like log processor also know to shut down.
        if not shutdown_event.is_set():
            print("Main wrapper: Pipeline ended unexpectedly or normally, ensuring shutdown event is set.")
            shutdown_event.set() # Signal other components if they are still running
            # Explicitly stop log processor if it wasn't via signal
            if _log_processor_instance and not _log_processor_instance._shutdown_event.is_set():
                await _log_processor_instance.stop()


if __name__ == "__main__":
    if not os.getenv("CLOUDFLARE_API_TOKEN") or not os.getenv("CLOUDFLARE_ZONE_ID"):
         print("ERROR: CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID environment variables not set.")
    else:
        print("Starting Cloudflare Instant Log streaming pipeline... Press Ctrl+C to stop.")
        try:
            asyncio.run(main_async_wrapper())
        except KeyboardInterrupt: 
            # This should ideally not be reached if signal handlers work as expected.
            # If it is, it might mean a very forceful/fast double Ctrl+C.
            print("Application forcefully interrupted by KeyboardInterrupt in __main__.")
        finally:
            print("Exiting main application block.")
            # Final check, ensure all aiohttp sessions are closed if errors occurred early.
            # This is a bit of a catch-all; proper cleanup should happen in task finally blocks.
            if _cf_manager_instance and _cf_manager_instance._session and not _cf_manager_instance._session.closed:
                print("Final check: Closing lingering aiohttp session.")
                asyncio.run(_cf_manager_instance.close_aiohttp_session())
