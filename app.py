from flask import Flask, render_template, request, jsonify
from scanner import URLScanner
import os

app = Flask(__name__)

# Initialize the scanner. 
# In a real app, use os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE" # Replace with your key, or leave blank to test heuristics only
scanner = URLScanner(vt_api_key=VIRUSTOTAL_API_KEY)

@app.route('/')
def home():
    """Renders the main dashboard."""
    return render_template('index.html')

@app.route('/api/scan_url', methods=['POST'])
def scan_url():
    """API endpoint to handle URL scanning requests from the frontend."""
    data = request.get_json()
    url_to_scan = data.get('url')

    if not url_to_scan:
        return jsonify({"error": "No URL provided"}), 400

    # Run the scanner logic
    try:
        results = scanner.scan(url_to_scan)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Run the app in debug mode for easy development
    app.run(debug=True, port=5000)