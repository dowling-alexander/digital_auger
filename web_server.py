import threading
import logging
from flask import Flask, render_template, jsonify
import time
from datetime import datetime # Import datetime for the timestamp filter
from logger import Logger

# Configure logging for the web server
logger = Logger(name="web_server.py", level=logging.DEBUG)

# This will be set by the main application when the web server is started
# It holds a reference to the TrafficAnalyzer instance
_traffic_analyzer_instance = None

def set_traffic_analyzer_instance(analyzer_instance):
    """
    Sets the TrafficAnalyzer instance that the web server will use to get data.
    This is called by the main application.
    """
    global _traffic_analyzer_instance
    _traffic_analyzer_instance = analyzer_instance
    logger.info("TrafficAnalyzer instance set for web server.")


app = Flask(__name__, template_folder='templates')


# --- Define and Register Jinja2 Filter Directly in web_server.py ---
def timestamp_to_datetime_filter(timestamp):
    """
    Jinja2 filter to convert a Unix timestamp to a human-readable datetime string.
    """
    if timestamp is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return "Invalid Timestamp"


# Register the filter with the Flask app's Jinja2 environment
app.jinja_env.filters['timestamp_to_datetime'] = timestamp_to_datetime_filter


# --- End Jinja2 Filter Registration ---


@app.route('/')
def index():
    """
    Renders the main HTML page, displaying initial data from TrafficAnalyzer.
    """
    if _traffic_analyzer_instance:
        packet_count = _traffic_analyzer_instance.get_packet_count()
        active_devices = list(_traffic_analyzer_instance.get_active_devices())  # Convert set to list for rendering

        # --- CHANGE 1: Defensive check for arp_requests for template rendering ---
        raw_arp_requests = _traffic_analyzer_instance.get_arp_requests()
        arp_requests_for_template = []
        for item in raw_arp_requests:
            if isinstance(item, dict):
                arp_requests_for_template.append(item)
            else:
                logger.error(f"Non-dictionary item found in ARP requests for template rendering: {type(item)} - {item}")
        # --- END CHANGE 1 ---

        # --- CHANGE 2: Get IDS alerts and pass to template ---
        ids_alerts = _traffic_analyzer_instance.get_ids_alerts()
        # --- END CHANGE 2 ---

        logger.info(
            f"Rendering index with {packet_count} packets, {len(active_devices)} devices, {len(arp_requests_for_template)} ARP requests, {len(ids_alerts)} alerts.")
        return render_template(
            'index.html',
            packet_count=packet_count,
            active_devices=active_devices,
            arp_requests=arp_requests_for_template,  # Use the cleaned list
            ids_alerts=ids_alerts  # Pass alerts to template
        )
    else:
        logger.warning("TrafficAnalyzer instance not available. Displaying placeholder.")
        return "<h1>Network Monitor Web Interface</h1><p>Traffic Analyzer not yet initialized. Please start the main application.</p>"


@app.route('/data')
def get_data():
    """
    Returns the latest network analysis data as JSON.
    This can be used by JavaScript for dynamic updates.
    """
    if _traffic_analyzer_instance:
        packet_count = _traffic_analyzer_instance.get_packet_count()
        active_devices = list(_traffic_analyzer_instance.get_active_devices())

        # --- CHANGE 3: Defensive check for arp_requests for JSON ---
        raw_arp_requests = _traffic_analyzer_instance.get_arp_requests()
        arp_requests_for_json = []
        for item in raw_arp_requests:
            if isinstance(item, dict):
                arp_requests_for_json.append(item)
            else:
                logger.error(f"Non-dictionary item found in ARP requests for JSON response: {type(item)} - {item}")
        # --- END CHANGE 3 ---

        # --- CHANGE 4: Get IDS alerts and include in JSON response ---
        ids_alerts = _traffic_analyzer_instance.get_ids_alerts()
        # --- END CHANGE 4 ---

        return jsonify({
            'packet_count': packet_count,
            'active_devices': active_devices,
            'arp_requests': arp_requests_for_json,  # Use the cleaned list
            'ids_alerts': ids_alerts  # Include alerts in JSON response
        })
    else:
        return jsonify({
            'error': 'TrafficAnalyzer not initialized'
        }), 503  # Service Unavailable


def run_web_server(host='0.0.0.0', port=8000, debug=False):
    """
    Function to run the Flask web server.
    This is intended to be called in a separate thread.
    """
    logger.info(f"Starting web server on http://{host}:{port}")
    try:
        app.run(host=host, port=port, debug=debug, use_reloader=False)
    except Exception as e:
        logger.error(f"Failed to start web server: {e}")


# This block is for testing web_server.py directly, not for main application use
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger.warning("Running web_server.py directly for testing. No TrafficAnalyzer will be active.")
    logger.warning("To run with TrafficAnalyzer, use the main_app.py script.")
    run_web_server(debug=True)  # Run in debug mode for direct testing