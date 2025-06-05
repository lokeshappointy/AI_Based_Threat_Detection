# main_logger.py
import asyncio
import signal
import os
from cloudflare_client import CloudflareLogSessionManager # Assuming this is now async
from websocket_handler import WebSocketLogReceiver
from config import WEBSOCKET_ERROR_RETRY_DELAY_SECONDS

running_tasks = []
shutdown_event = asyncio.Event()

def signal_handler(signum, frame):
    print(f"\nSignal {signal.Signals(signum).name} received, initiating graceful shutdown...")
    shutdown_event.set()


async def run_log_pipeline():
    cf_manager = CloudflareLogSessionManager()
    ws_receiver_task = None # Keep track of the current receiver task

    try:
        while not shutdown_event.is_set():
            websocket_url, session_id = await cf_manager.create_instant_log_session()

            if websocket_url and not shutdown_event.is_set():
                print(f"Obtained WebSocket URL for session {session_id}")
                current_ws_receiver = WebSocketLogReceiver(websocket_url, session_id, shutdown_event)
                
                print(f"Starting WebSocket receiver task for session {session_id}...")
                ws_receiver_task = asyncio.create_task(current_ws_receiver.start())
                running_tasks.append(ws_receiver_task) # Add to global list for shutdown
                
                try:
                    await ws_receiver_task # This line waits for the receiver task to finish
                except asyncio.CancelledError:
                    print(f"Main loop: WebSocket receiver task for session {session_id} was cancelled.")
                    # If cancelled from outside (e.g. global shutdown), break the main while loop
                    if shutdown_event.is_set(): 
                        break 
                except Exception as e_task:
                    print(f"Main loop: WebSocket receiver task for {session_id} ended with error: {e_task}")
                finally:
                    if ws_receiver_task in running_tasks:
                        running_tasks.remove(ws_receiver_task)
                
                if shutdown_event.is_set():
                    print("Main loop: Shutdown event detected after session handling. Exiting.")
                    break
                
                print(f"Main loop: Session {session_id} concluded. Preparing to create a new session after a delay...")
                await asyncio.sleep(WEBSOCKET_ERROR_RETRY_DELAY_SECONDS)
            
            elif shutdown_event.is_set():
                print("Main loop: Shutdown requested during session creation attempt.")
                break
            else:
                print("Main loop: Failed to obtain WebSocket URL. Retrying as per manager's logic.")
                # cf_manager.create_instant_log_session() has its own retry, so this loop will just re-attempt.
                # A small delay here might be good if create_instant_log_session can return None very quickly after many failures.
                await asyncio.sleep(5) # Small delay before re-calling create_instant_log_session

    finally:
        print("Main loop: Cleaning up CloudflareLogSessionManager...")
        await cf_manager.close_aiohttp_session() # Ensure aiohttp session is closed

    print("Main log pipeline loop has finished.")


async def main_with_graceful_shutdown():
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(initiate_shutdown(s))) # Changed to initiate_shutdown

    print("Starting Cloudflare Instant Log streaming pipeline... Press Ctrl+C to stop.")
    
    main_pipeline_task = None
    try:
        main_pipeline_task = asyncio.create_task(run_log_pipeline())
        await main_pipeline_task
    except asyncio.CancelledError:
        print("Main pipeline task (run_log_pipeline) was cancelled.")
    except Exception as e_main:
        print(f"Unhandled exception in main_with_graceful_shutdown: {e_main}")
    finally:
        print("Main_with_graceful_shutdown: Ensuring all tasks are cancelled due to exit or error...")
        if not shutdown_event.is_set(): # If shutdown wasn't triggered by signal, trigger it now
            shutdown_event.set()

        # Wait for a brief moment to allow tasks to respond to shutdown_event
        await asyncio.sleep(0.1) 

        tasks_to_cancel = [t for t in running_tasks if t is not main_pipeline_task and not t.done()]
        if main_pipeline_task and not main_pipeline_task.done():
            tasks_to_cancel.append(main_pipeline_task)
        
        if tasks_to_cancel:
            print(f"Cancelling {len(tasks_to_cancel)} outstanding tasks...")
            for task in tasks_to_cancel:
                task.cancel()
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
            print("Gathered results from cancelled tasks.")
        else:
            print("No outstanding tasks to cancel.")
        
        # Explicitly close the loop on some systems if needed, or manage through higher-level asyncio.run
        # This can sometimes help with lingering resources or warnings on exit.
        # However, asyncio.run() usually handles loop closing.
        # active_asyncio_tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        # if active_asyncio_tasks:
        #     print(f"Waiting for {len(active_asyncio_tasks)} remaining asyncio tasks to complete...")
        #     await asyncio.gather(*active_asyncio_tasks, return_exceptions=True)


async def initiate_shutdown(signal_obj): # Renamed from shutdown to avoid conflict
    """Sets the shutdown event and gives tasks a moment to react."""
    print(f"Received exit signal {signal_obj.name if hasattr(signal_obj, 'name') else signal_obj}...")
    if not shutdown_event.is_set():
        print("Signalling all components to shut down via event.")
        shutdown_event.set()
    else:
        print("Shutdown already in progress.")

if __name__ == "__main__":
    if not os.getenv("CLOUDFLARE_API_TOKEN") or not os.getenv("CLOUDFLARE_ZONE_ID"): # Ensure this env var name matches your .env
         print("ERROR: CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID_PRODUCTION environment variables not set.")
    else:
        try:
            asyncio.run(main_with_graceful_shutdown())
        except KeyboardInterrupt: 
            print("\nApplication forcefully interrupted by KeyboardInterrupt in __main__.")
        finally:
            print("Exiting main application block.")