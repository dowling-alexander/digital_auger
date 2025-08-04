import time
import logging

from logger import Logger
from scapy.all import Packet, IP, ARP, DNS, DNSQR, TCP  # Import necessary layers
from scapy.layers.inet import UDP

logger = Logger(name="ids_rules.py", level=logging.DEBUG)


class IDSRules:
    """
    A class to define and apply various Intrusion Detection System rules.
    It processes packets and logs/stores detected anomalies.
    """

    def __init__(self):
        self.alerts = []  # List to store detected alerts
        self._ip_packet_counts = {}  # For tracking high volume
        self._arp_request_counts = {}  # For tracking excessive ARP requests
        self._last_cleanup_time = time.time()  # For periodic cleanup of old counts

        # Configuration for rules
        self.HIGH_VOLUME_THRESHOLD = 500  # Packets per TIME_WINDOW
        self.HIGH_VOLUME_TIME_WINDOW = 5  # Seconds

        self.EXCESSIVE_ARP_THRESHOLD = 20  # ARP requests per TIME_WINDOW
        self.EXCESSIVE_ARP_TIME_WINDOW = 5  # Seconds

        self.MALICIOUS_DNS_DOMAINS = {
            "badsite.com", "malware-c2.net", "heresy.org",  # Example malicious domains
            "eviltracker.xyz", "phishing.biz"
        }

        logger.info("IDS Rules engine initialized.")

    def _add_alert(self, rule_name: str, severity: str, description: str, source_ip: str = None, source_mac: str = None,
                   details: dict = None):
        """
        Helper to add a new alert to the alerts list.
        """
        alert = {
            "timestamp": time.time(),
            "rule": rule_name,
            "severity": severity,
            "description": description,
            "source_ip": source_ip,
            "source_mac": source_mac,
            "details": details if details is not None else {}
        }
        self.alerts.append(alert)
        logger.warning(f"ALERT ({severity}): {description} (Rule: {rule_name}) from {source_ip or 'N/A'}")

    def _cleanup_old_counts(self):
        """
        Periodically cleans up old packet/ARP counts to prevent memory bloat
        and ensure rate limits are based on recent activity.
        """
        current_time = time.time()
        if current_time - self._last_cleanup_time > 60:  # Clean up every 60 seconds
            logger.debug("Cleaning up old IDS rule counts.")

            # Clean up IP packet counts
            ips_to_remove = [
                ip for ip, data in self._ip_packet_counts.items()
                if (current_time - data['last_reset_time']) > (self.HIGH_VOLUME_TIME_WINDOW * 2)
                # Keep for a bit longer
            ]
            for ip in ips_to_remove:
                del self._ip_packet_counts[ip]

            # Clean up ARP request counts
            arps_to_remove = [
                ip for ip, data in self._arp_request_counts.items()
                if (current_time - data['last_reset_time']) > (self.EXCESSIVE_ARP_TIME_WINDOW * 2)
            ]
            for ip in arps_to_remove:
                del self._arp_request_counts[ip]

            self._last_cleanup_time = current_time

    def analyze_packet(self, packet: Packet):
        """
        Analyzes a single packet against defined IDS rules.
        """
        self._cleanup_old_counts()  # Perform periodic cleanup

        src_ip = None
        src_mac = None

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            src_mac = packet.src if hasattr(packet, 'src') else 'Unknown'

            # Rule: High Volume from Single Source (DDoS/Flood Attempt)
            self._check_high_volume(packet, src_ip, src_mac)

            # Rule: Traffic to Unusual Ports
            self._check_unusual_ports(packet, src_ip, src_mac)

        if packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            # Rule: Excessive ARP Requests/Replies
            self._check_excessive_arp(packet, src_ip, src_mac)

        if packet.haslayer(DNS):
            # Rule: DNS Requests to Known Malicious Domains
            self._check_malicious_dns(packet, src_ip, src_mac)

        # Add more rules here as needed

    def _check_high_volume(self, packet: Packet, src_ip: str, src_mac: str):
        """Rule: Detects high volume of packets from a single source IP."""
        current_time = time.time()
        if src_ip not in self._ip_packet_counts:
            self._ip_packet_counts[src_ip] = {'count': 0, 'last_reset_time': current_time}

        # Reset count if time window has passed
        if (current_time - self._ip_packet_counts[src_ip]['last_reset_time']) > self.HIGH_VOLUME_TIME_WINDOW:
            self._ip_packet_counts[src_ip]['count'] = 0
            self._ip_packet_counts[src_ip]['last_reset_time'] = current_time

        self._ip_packet_counts[src_ip]['count'] += 1

        if self._ip_packet_counts[src_ip]['count'] > self.HIGH_VOLUME_THRESHOLD:
            self._add_alert(
                rule_name="High Volume (Ork Waaagh!)",
                severity="HIGH",
                description=f"Excessive packet volume detected from {src_ip}",
                source_ip=src_ip,
                source_mac=src_mac,
                details={"packets_in_window": self._ip_packet_counts[src_ip]['count'],
                         "time_window": self.HIGH_VOLUME_TIME_WINDOW}
            )
            # Optionally, reset count immediately after alert to avoid repeated alerts for same burst
            self._ip_packet_counts[src_ip]['count'] = 0

    def _check_unusual_ports(self, packet: Packet, src_ip: str, src_mac: str):
        """Rule: Detects traffic to/from unusual ports."""
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            # Define a set of common/expected ports
            common_ports = {80, 443, 22, 21, 23, 25, 110, 143, 53, 67, 68, 123, 3389, 8000}  # Add more as needed

            dst_port = packet[TCP].dport if packet.haslayer(TCP) else (
                packet[UDP].dport if packet.haslayer(UDP) else None)
            src_port = packet[TCP].sport if packet.haslayer(TCP) else (
                packet[UDP].sport if packet.haslayer(UDP) else None)

            if dst_port and dst_port not in common_ports and dst_port > 1024:  # Focus on high-numbered ports not in common_ports
                self._add_alert(
                    rule_name="Unusual Port (Forbidden Gateway)",
                    severity="MEDIUM",
                    description=f"Traffic to unusual destination port {dst_port} from {src_ip}",
                    source_ip=src_ip,
                    source_mac=src_mac,
                    details={"port": dst_port, "direction": "destination"}
                )
            if src_port and src_port not in common_ports and src_port > 1024:  # Focus on high-numbered ports not in common_ports
                self._add_alert(
                    rule_name="Unusual Port (Forbidden Gateway)",
                    severity="MEDIUM",
                    description=f"Traffic from unusual source port {src_port} from {src_ip}",
                    source_ip=src_ip,
                    source_mac=src_mac,
                    details={"port": src_port, "direction": "source"}
                )

    def _check_excessive_arp(self, packet: Packet, src_ip: str, src_mac: str):
        """Rule: Detects excessive ARP requests from a single source."""
        if packet.haslayer(ARP) and packet[ARP].op == 1:  # Only check for ARP requests
            current_time = time.time()
            if src_ip not in self._arp_request_counts:
                self._arp_request_counts[src_ip] = {'count': 0, 'last_reset_time': current_time}

            # Reset count if time window has passed
            if (current_time - self._arp_request_counts[src_ip]['last_reset_time']) > self.EXCESSIVE_ARP_TIME_WINDOW:
                self._arp_request_counts[src_ip]['count'] = 0
                self._arp_request_counts[src_ip]['last_reset_time'] = current_time

            self._arp_request_counts[src_ip]['count'] += 1

            if self._arp_request_counts[src_ip]['count'] > self.EXCESSIVE_ARP_THRESHOLD:
                self._add_alert(
                    rule_name="Excessive ARP (Gretchin Swarm)",
                    severity="HIGH",
                    description=f"High rate of ARP requests from {src_ip}",
                    source_ip=src_ip,
                    source_mac=src_mac,
                    details={"requests_in_window": self._arp_request_counts[src_ip]['count'],
                             "time_window": self.EXCESSIVE_ARP_TIME_WINDOW}
                )
                # Optionally, reset count immediately after alert
                self._arp_request_counts[src_ip]['count'] = 0

    def _check_malicious_dns(self, packet: Packet, src_ip: str, src_mac: str):
        """Rule: Detects DNS queries to known malicious domains."""
        if packet.haslayer(DNSQR):  # DNS Query Record
            try:
                query_name = packet[DNSQR].qname.decode('utf-8').strip('.')
                if query_name in self.MALICIOUS_DNS_DOMAINS:
                    self._add_alert(
                        rule_name="Malicious DNS (Forbidden Knowledge Access)",
                        severity="CRITICAL",
                        description=f"DNS query to known malicious domain: {query_name}",
                        source_ip=src_ip,
                        source_mac=src_mac,
                        details={"queried_domain": query_name}
                    )
            except Exception as e:
                logger.debug(f"Could not decode DNS query name: {e}")

    def get_all_alerts(self) -> list:
        """
        Returns a copy of the list of all detected alerts.
        """
        return list(self.alerts)

    def clear_alerts(self):
        """
        Clears all stored alerts.
        """
        self.alerts.clear()
        logger.info("All IDS alerts cleared.")
