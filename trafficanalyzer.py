import threading
import time
import logging

from ids_rules import IDSRules
from logger import Logger
from scapy.all import sniff, Packet, IP, ARP # Import necessary Scapy components and IP, ARP layers

# Configure logging for better visibility of what the analyzer is doing
logger = Logger(name="trafficanalyzer.py", level=logging.DEBUG)
class TrafficAnalyzer:
    """
    A class to analyze network traffic using Scapy in a separate thread.
    It counts the number of packets reviewed and provides methods to start,
    stop, and query the analysis status and packet count.
    Now also tracks active devices, ARP requests, and integrates IDS rules.
    """

    def __init__(self, interface: str = None, packet_limit: int = None, timeout: int = None):
        """
        Initializes the TrafficAnalyzer.

        Args:
            interface (str, optional): The network interface to sniff on (e.g., "eth0", "wlan0").
                                       If None, Scapy will attempt to find a suitable interface.
            packet_limit (int, optional): The maximum number of packets to capture before stopping.
                                          If None, it will capture indefinitely until stopped.
            timeout (int, optional): The maximum duration in seconds to capture packets.
                                     If None, it will capture indefinitely until stopped.
        """
        self.interface = interface
        self.packet_limit = packet_limit
        self.timeout = timeout
        self._packet_count = 0
        self._is_running = False
        self._stop_event = threading.Event()
        self._sniff_thread = None

        self._active_devices = set()
        self._arp_requests = []# This is the list that stores ARP request dictionaries
        self._ids_rules = IDSRules() # Instantiate the IDS Rules engine

        logger.info(f"TrafficAnalyzer initialized for interface: {self.interface or 'default'}")
        if self.packet_limit:
            logger.info(f"Packet limit set to: {self.packet_limit}")
        if self.timeout:
            logger.info(f"Timeout set to: {self.timeout} seconds")

    def _packet_callback(self, packet: Packet):
        """
        Callback function executed for each packet sniffed.
        Increments the packet count and performs additional analysis for
        active devices, ARP requests, and IDS rules.
        """
        self._packet_count += 1

        # --- Track Active Devices ---
        # Look for IP packets to get source IP and MAC
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            # Try to get MAC address from the Ethernet layer if available
            src_mac = packet.src if hasattr(packet, 'src') else 'N/A'
            if src_ip and src_mac!= 'N/A':
                self._active_devices.add((src_ip, src_mac))
            elif src_ip: # Add just IP if MAC isn't readily available
                self._active_devices.add((src_ip, 'Unknown'))

        # Look for ARP packets to get sender IP and MAC
        if packet.haslayer(ARP):
            # ARP request (op=1) or reply (op=2)
            sender_ip = packet.psrc
            sender_mac = packet.hwsrc
            if sender_ip and sender_mac:
                self._active_devices.add((sender_ip, sender_mac))

            # --- Report ARP Requests (THIS IS WHERE THE DICTIONARY IS CREATED AND ADDED) ---
            if packet.op == 1: # ARP Request
                # Store relevant details: sender IP, sender MAC, target IP
                arp_info = {
                    "timestamp": time.time(),
                    "sender_ip": packet.psrc,
                    "sender_mac": packet.hwsrc,
                    "target_ip": packet.pdst
                }
                # Add the dictionary to the _arp_requests list
                self._arp_requests.append(arp_info)
                logger.debug(f"ARP Request detected: {arp_info}")

        # --- Pass packet to IDS Rules engine for analysis ---
        self._ids_rules.analyze_packet(packet)


    def _sniff_target(self):
        """
        The target function for the sniffing thread.
        This runs the Scapy sniff operation.
        """
        logger.info(f"Sniffing thread started on interface: {self.interface or 'auto'}")
        try:
            # Dynamically build arguments for sniff to avoid passing None if not set
            sniff_kwargs = {
                "iface": self.interface,
                "prn": self._packet_callback,
                "store": 0, # Prevent Scapy from storing packets in memory
                "stop_filter": lambda x: self._stop_event.is_set()
            }
            if self.packet_limit is not None:
                sniff_kwargs["count"] = self.packet_limit
            if self.timeout is not None:
                sniff_kwargs["timeout"] = self.timeout

            # Call sniff with the prepared arguments
            sniff(**sniff_kwargs)

        except PermissionError:
            logger.error("Permission denied. Scapy sniffing often requires root/administrator privileges.")
            logger.error("Try running your script with 'sudo python your_script.py' on Linux/macOS.")
        except Exception as e:
            logger.error(f"An error occurred during sniffing: {e}")
        finally:
            self._is_running = False # Ensure flag is set to False when sniffing stops
            logger.info("Sniffing thread stopped.")

    def start_analysis(self):
        """
        Starts the network traffic analysis in a separate thread.
        Resets all counters and stored data.
        """
        if not self._is_running:
            self._packet_count = 0 # Reset count on new start
            self._active_devices.clear() # Reset active devices
            self._arp_requests.clear()   # Reset ARP requests
            self._ids_rules = IDSRules() # Re-initialize IDS rules to clear its state
            self._stop_event.clear() # Clear any previous stop signal
            self._is_running = True
            self._sniff_thread = threading.Thread(target=self._sniff_target)
            self._sniff_thread.daemon = True # Allow main program to exit even if thread is running
            self._sniff_thread.start()
            logger.info("Traffic analysis started.")
        else:
            logger.warning("Traffic analysis is already running.")

    def stop_analysis(self):
        """
        Stops the network traffic analysis.
        Waits for the sniffing thread to finish.
        """
        if self._is_running:
            logger.info("Signaling traffic analysis to stop...")
            self._stop_event.set() # Set the event to signal the thread to stop
            if self._sniff_thread and self._sniff_thread.is_alive():
                self._sniff_thread.join(timeout=5) # Wait for the thread to finish (with a timeout)
                if self._sniff_thread.is_alive():
                    logger.warning("Sniffing thread did not terminate gracefully within timeout.")
            self._is_running = False
            logger.info("Traffic analysis stopped.")
        else:
            logger.warning("Traffic analysis is not running.")

    def get_packet_count(self) -> int:
        """
        Returns the total number of packets reviewed so far.
        """
        return self._packet_count

    def get_active_devices(self) -> set:
        """
        Returns a set of unique (IP, MAC) tuples representing active devices observed.
        'Unknown' is used for MAC if not available.
        """
        return self._active_devices

    def get_arp_requests(self) -> list:
        """
        Returns a list of dictionaries, where each dictionary contains details
        (timestamp, sender_ip, sender_mac, target_ip) of observed ARP requests.
        """
        # --- CRITICAL FIX: Return a copy of the list to prevent concurrent modification issues ---
        return list(self._arp_requests)
        # --- END CRITICAL FIX ---

    def get_ids_alerts(self) -> list:
        """
        Returns a list of detected IDS alerts.
        """
        return self._ids_rules.get_all_alerts()

    def is_running(self) -> bool:
        """
        Checks if the traffic analysis is currently active.
        """
        return self._is_running

    def __del__(self):
        """
        Ensures the sniffing thread is stopped when the object is garbage collected.
        """
        self.stop_analysis()
