import PIL
import threading
import sys
import time
import os
import logging
import threading
import subprocess
import signal
import web_server
import socket

from trafficanalyzer import TrafficAnalyzer


from display import Display
from init_shared import shared_data
from logger import Logger

logger = Logger(name="Digital_Auger.py", level=logging.DEBUG)

class Digital_Auger:

    def __init__(self):
        name = "tech auger"
        logger.info("made it to initialise")
        self.orchestrator_thread = None
        self.orchestrator = None

    def run(self):
        logger.info("Begin incantations")

    @staticmethod
    def start_display():
        logger.info("made it to start display")
        display = Display()
        display_thread = threading.Thread(target=display.run)
        display_thread.start()
        return display_thread

    def is_wifi_connected(self):
        """Checks for Wi-Fi connectivity using the nmcli command."""
        result = subprocess.Popen(['nmcli', '-t', '-f', 'active', 'dev', 'wifi'], stdout=subprocess.PIPE, text=True).communicate()[0]
        self.wifi_connected = 'yes' in result
        return self.wifi_connected


def handle_exit(sig, frame, digital_auger_thread):
    """Handles the termination of the main, display, and web threads."""
    shared_data.should_exit = True
    shared_data.orchestrator_should_exit = True  # Ensure orchestrator stops
    shared_data.display_should_exit = True  # Ensure display stops
    #handle_exit_display(sig, frame, display_thread)
    #if display_thread.is_alive():
    #    display_thread.join()
    if digital_auger_thread.is_alive():
        digital_auger_thread.join()
    #if web_thread.is_alive():
    #    web_thread.join()
    logger.info("Main loop finished. Clean exit.")
    sys.exit(0)  # Used sys.exit(0) instead of exit(0)




if __name__ == "__main__":
    logger.info("Awakening the machine spirit threads")

    #report out the ip adress for web portal
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Connect to an external host (doesn't send data)
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1 (Check network connection)"
    logger.info(f"Omnissiah Portal Interface: {local_ip}")


    try:

        logger.info("Load the machine spirits memories...")
        shared_data.get_default_config()
        #logger.info("Initialise the dataslate.....")
        #display_thread = Digital_Auger.start_display()

        logger.info("Awaken the Digital Auger Thread.....")
        digital_auger = Digital_Auger()
        digital_auger_thread = threading.Thread(target=digital_auger.run)
        digital_auger_thread.start()
        analyzer = TrafficAnalyzer()

        logger.info("The slate begins to hum.....")
        web_server.set_traffic_analyzer_instance(analyzer)
        web_thread = threading.Thread(target=web_server.run_web_server)
        web_thread.daemon = True # Allow main program to exit even if web server is running
        web_thread.start()
        # Using default host and port from web_server.py (0.0.0.0:8000)
        logger.info(f"The server accessible at http://{local_ip}:8000")
        # --- END WEB THREAD CREATION ---

        try:
            logger.info("Watch the streams for heresy...")
            analyzer.start_analysis()

            # Loop indefinitely while the analyzer is running
            while analyzer.is_running():
                current_packets = analyzer.get_packet_count()
                active_devices = analyzer.get_active_devices()
                #arp_requests = analyzer.get_arp_requests()
                ids_alerts = analyzer.get_ids_alerts() # Get IDS alerts

                logger.info(f"\n--- Console Update ---")
                logger.info(f"Packets reviewed: {current_packets}")
                logger.info(f"Active Devices: {len(active_devices)}")
                for ip, mac in list(active_devices)[:5]:
                    logger.info(f"  - IP: {ip}, MAC: {mac}")
                if len(active_devices) > 5:
                    logger.info(f"  ... and {len(active_devices) - 5} more.")
                #logger.info(f"ARP Requests: {len(arp_requests)}")
                logger.info(f"IDS Alerts: {len(ids_alerts)}")
                for alert in ids_alerts[-2:]: # Print last 2 alerts for console brevity
                    logger.info(f"  - ALERT [{alert['severity']}]: {alert['description']} (Rule: {alert['rule']})")
                logger.info("--------------------")

                time.sleep(10)

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        signal.signal(signal.SIGINT, lambda sig, frame: handle_exit(sig, frame, digital_auger_thread))
        signal.signal(signal.SIGTERM, lambda sig, frame: handle_exit(sig, frame, digital_auger_thread))


    except Exception as e:
        logger.error(f"Unable to start")
        exit(1)

