# main.py

import time
import os
from src.display_manager import DisplayManager
from src.network_monitor import NetworkMonitor
from config import settings

# --- Configuration (loaded from settings.py) ---
# This makes it easy to change settings without editing main.py directly
NETWORK_INTERFACE = settings.NETWORK_INTERFACE
IDLE_IMAGE_PATH = settings.IDLE_IMAGE_PATH
ALERT_IMAGE_PATH = settings.ALERT_IMAGE_PATH
DISPLAY_WIDTH = settings.DISPLAY_WIDTH  # e.g., 122
DISPLAY_HEIGHT = settings.DISPLAY_HEIGHT # e.g., 250 (for Waveshare 2.13 V2 in portrait)
# Add other display specific settings from settings.py if needed

# --- Global Flags / State ---
# This flag helps manage what the display is currently showing
displaying_alert = False

# --- Callback Function for Network Monitor ---
# This function will be called by the network_monitor whenever a rule is triggered.
def handle_alert(alert_message):
    global displaying_alert
    print(f"[ALERT DETECTED]: {alert_message}")

    # Only update display if we're not already showing an alert
    if not displaying_alert:
        print("Updating display to alert state...")
        display_manager.clear_display()
        display_manager.display_image(ALERT_IMAGE_PATH)
        # Optionally, display the specific alert message as text
        # display_manager.display_text(alert_message, x=10, y=100, font_size=16)
        display_manager.update_full_display() # For e-paper, a full update is often required for new content
        displaying_alert = True

        # In Stage 1, we might just keep the alert displayed indefinitely
        # or have a simple timer to revert after some time.
        # For this example, it stays on alert.
        # For more advanced stages, you'd have a queue of alerts and a more dynamic display.

def main():
    global displaying_alert

    print("Initializing Digital Scribe...")

    # --- 1. Initialize Display ---
    # The DisplayManager will handle setting up the SPI, GPIO, etc.
    try:
        display_manager = DisplayManager(width=DISPLAY_WIDTH, height=DISPLAY_HEIGHT)
        display_manager.init_display()
        print("Display initialized.")
    except Exception as e:
        print(f"Error initializing display: {e}")
        print("Continuing without display functionality.")
        # If display fails, perhaps still try to monitor traffic and log to console
        display_manager = None # Set to None to prevent further display calls


    # --- 2. Display Static Idle Image ---
    if display_manager:
        try:
            print(f"Loading idle image from {IDLE_IMAGE_PATH}...")
            display_manager.clear_display() # Clear anything from previous power cycles
            display_manager.display_image(IDLE_IMAGE_PATH)
            # You might want to display some initial status text as well
            # display_manager.display_text("Network Augur Online", x=20, y=20, font_size=18)
            display_manager.update_full_display() # Push the image to the e-paper
            print("Idle image displayed.")
        except Exception as e:
            print(f"Error displaying idle image: {e}")
            display_manager = None # Disable display if it's causing issues


    # --- 3. Start Network Monitoring ---
    # The NetworkMonitor will run its sniffing in a separate thread to keep main.py responsive
    # We pass our handle_alert function to it, so it knows what to call when a rule triggers.
    try:
        print(f"Starting network monitor on interface: {NETWORK_INTERFACE}...")
        network_monitor = NetworkMonitor(interface=NETWORK_INTERFACE, alert_callback=handle_alert)
        network_monitor.start_monitoring() # This method should start sniffing in a non-blocking way
        print("Network monitoring active. Awaiting anomalies...")
    except Exception as e:
        print(f"Error starting network monitor: {e}")
        print("Exiting due to critical error.")
        if display_manager:
            display_manager.clear_display()
            display_manager.display_text("ERROR: Monitor Offline", x=10, y=10, font_size=16)
            display_manager.update_full_display()
        return


    # --- 4. Main Loop / Keep Alive ---
    # This loop keeps the main script running.
    # In more complex projects, this loop might handle user input, periodic tasks, etc.
    # For Stage 1, it mostly just keeps the program alive so the background monitoring works.
    try:
        while True:
            # You could add a small delay to reduce CPU usage if nothing else is happening
            time.sleep(1)

            # Optional: Periodically revert display to idle if no new alerts
            # This would require more sophisticated logic in handle_alert
            # and a timestamp for the last alert.
            # For Stage 1, simpler to just stay on alert or manually reset.

    except KeyboardInterrupt:
        print("\nDigital Scribe shutting down...")
    finally:
        # --- Cleanup ---
        # Ensure resources are released gracefully
        if network_monitor:
            network_monitor.stop_monitoring() # Stop the sniffing thread
            print("Network monitor stopped.")
        if display_manager:
            display_manager.sleep_display() # Put e-paper in low power mode
            print("Display put to sleep.")
        print("Digital Scribe offline.")

if __name__ == "__main__":
    main()