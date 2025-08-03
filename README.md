⚙️ Adeptus Mechanicus Network Auspex 🛡️
Introduction
Welcome, Tech-Priest, to the Adeptus Mechanicus Network Auspex! This project transforms your network into a domain of the Omnissiah, vigilantly monitoring for any digital heresy, Xenos incursions, or Machine Spirit anomalies. Leveraging the arcane arts of Python and Scapy, this system acts as your personal Intrusion Detection System (IDS), providing real-time insights into network traffic, active devices, and potential threats through a web-based interface.

Guard your network's integrity with the unwavering vigilance of the Adeptus Mechanicus!

Features
This Auspex is equipped with several key functionalities to ensure the purity of your network's data-streams:

Packet Count Augmentation: Continuously tracks and reports the total number of data packets traversing your network.

Active Servitor (Device) Manifestation: Identifies and lists all active devices (IP and MAC addresses) communicating on your network, revealing the presence of all connected machine spirits.

Heresy & Intrusion Alerts: Utilizes custom-defined rules to detect suspicious activities, categorizing them by severity (Critical, High, Medium, Low).

High Volume Detection (Ork Waaagh! Spike): Identifies sudden, excessive packet floods from single sources.

Unusual Port Activity (Forbidden Gateways): Flags connections attempting to use non-standard or unexpected network ports.

Malicious DNS Queries (Forbidden Knowledge Access): Alerts on attempts to resolve domains known to be associated with malefic entities or forbidden knowledge.

(Future rules can be easily added to detect more forms of heresy!)

Web-Based Data-Slate Interface: A Flask-powered web server provides a clean, 40k-themed dashboard to visualize network metrics and alerts in real-time.

Modular Design: Components are separated into distinct Python files (traffic_analyzer.py, ids_rules.py, web_server.py) for easy maintenance and expansion.

Graceful Shutdown: Implements signal handling for clean termination of all monitoring threads.

Installation
Before deploying the Auspex, ensure your system is prepared.

Clone the Repository (or download the files):

git clone <repository_url>
cd <repository_directory>

Create a Python Virtual Environment (Recommended):

python -m venv .venv

Activate the Virtual Environment:

Windows:

.venv\Scripts\activate

Linux/macOS:

source .venv/bin/activate

Install Dependencies:

pip install scapy Flask

Install Npcap (Windows) or libpcap-dev (Linux/macOS):

Windows: Scapy requires Npcap. Download and install it from the official Npcap website: https://nmap.org/npcap/

Linux (Debian/Ubuntu):

sudo apt-get update
sudo apt-get install libpcap-dev

macOS: libpcap is usually pre-installed.

Project Structure
Ensure your project directory is organized as follows:

your_project_directory/
├── main_app.py             # Main application entry point (your Digital Auger script)
├── traffic_analyzer.py     # Core packet sniffing and data collection
├── ids_rules.py            # Definitions for all Intrusion Detection System rules
├── web_server.py           # Flask web server for the dashboard
└── templates/
    └── index.html          # HTML template for the web dashboard

Configuration
Before initiating the Auspex, a minor configuration adjustment is required.

Open main_app.py and modify the NETWORK_INTERFACE variable to match your system's network adapter name.

# main_app.py

# --- Configuration ---
NETWORK_INTERFACE = "wlan0"  # <--- CHANGE THIS TO YOUR ACTUAL NETWORK INTERFACE!
# ... rest of the code ...

To find your interface name:

Linux/macOS: Open a terminal and run ifconfig or ip a. Look for names like eth0, wlan0, en0, etc.

Windows: Open Command Prompt or PowerShell and run ipconfig. Look for names like "Ethernet" or "Wi-Fi".

Usage
To awaken the Auspex and begin monitoring your network:

Run the Main Application:
Open your terminal or command prompt, navigate to your project directory, and execute main_app.py. Crucially, this application requires administrative/root privileges to sniff network traffic.

Linux/macOS:

sudo python3 main_app.py

Windows (Run Command Prompt/PowerShell as Administrator):

python main_app.py

Access the Web Interface:
Once the application starts, you'll see a log message indicating the web server's address, for example:
INFO - MainApp - Web server accessible at http://192.168.1.X:8000

Open a web browser on any device connected to the same local network as the machine running the Auspex, and navigate to the displayed IP address and port (e.g., http://192.168.1.X:8000).

The web dashboard will update automatically every 5 seconds, displaying real-time network statistics and any detected anomalies.

IDS Rules Explained
The ids_rules.py file contains the logic for detecting various forms of network heresy. Here's a brief overview of the implemented rules:

High Volume (Ork Waaagh! Spike):

Purpose: Detects Distributed Denial of Service (DDoS) attempts or network floods.

Mechanism: Monitors the rate of packets originating from a single IP address. If the packet count exceeds a configured HIGH_VOLUME_THRESHOLD within a HIGH_VOLUME_TIME_WINDOW, an alert is triggered.

Unusual Port (Forbidden Gateway):

Purpose: Identifies attempts to communicate on non-standard or high-numbered ports, which can indicate malware activity, unauthorized services, or suspicious probing.

Mechanism: Checks the source and destination ports of TCP and UDP packets against a list of common, expected ports. Alerts are generated for traffic on unusual high-numbered ports.

Malicious DNS (Forbidden Knowledge Access):

Purpose: Flags attempts by devices on your network to resolve domain names known to be associated with malicious command-and-control servers, phishing sites, or botnets.

Mechanism: Inspects DNS query records and compares the queried domain name against a predefined blacklist of MALICIOUS_DNS_DOMAINS.

You can expand these rules or add entirely new ones within ids_rules.py to tailor the Auspex to your specific network's needs!

Important Notes
Permissions: Scapy requires elevated privileges to capture network traffic. Always run the main_app.py script with sudo (Linux/macOS) or as an Administrator (Windows).

Network Interface: Ensure the NETWORK_INTERFACE variable in main_app.py is correctly set to your active network adapter. Incorrect configuration will prevent traffic analysis.

Daemon Threads: The network analyzer and web server run in daemon threads. This means they will automatically terminate when the main Python process exits (e.g., when you press Ctrl+C).

Future Enhancements
The Omnissiah's work is never truly complete. Future enhancements for the Adeptus Mechanicus Network Auspex could include:

E-Paper Display Integration: Directly display critical alerts and key metrics on a physical E-Paper display, providing a dedicated, low-power visual readout of your network's status.

Historical Data Logging: Implement persistent storage (e.g., a simple database or log files) to store historical packet data, device lists, and alerts for later analysis and auditing.

Advanced Threat Signatures: Develop more sophisticated IDS rules, potentially incorporating machine learning for anomaly detection or integration with external threat intelligence feeds.

Notification System: Add functionality to send notifications (e.g., email, push notifications) when critical alerts are triggered.

Interactive Controls: Allow basic interaction with the web interface to clear alerts, pause/resume monitoring, or adjust rule thresholds.

For the glory of the Machine God! May your network remain uncorrupted.
