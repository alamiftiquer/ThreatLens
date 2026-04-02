# ThreatLens 🔍
**AI-Driven Phishing & Malicious Payload Detector**

A proactive cybersecurity tool designed to analyze URLs for phishing indicators, malicious payloads, and social engineering tactics. This project was developed as a practical application of enterprise security principles during the VOIS AICTE Cyber Security Internship.

## 🚀 Overview
ThreatLens provides a dual-layered approach to threat detection. It utilizes local heuristic analysis to rapidly identify structural anomalies in URLs (such as IP-based routing, excessive subdomains, and suspicious keywords) and cross-references data with the VirusTotal API for deep-scan threat intelligence. 

## ✨ Features
* **Heuristic Engine:** Statically analyzes URL structures to catch zero-day phishing attempts before they are flagged by major security vendors.
* **Threat Intelligence Integration:** Automatically queries the VirusTotal v3 API to retrieve global reputation scores and malicious flags.
* **Risk Scoring Algorithm:** Calculates a weighted overall "Threat Score" (0-100) and categorizes risk into LOW, MEDIUM, or HIGH tiers.
* **Interactive Dashboard:** A clean, dark-mode web UI built with HTML/CSS/JS to provide real-time feedback and detailed findings to the user.
* **RESTful API:** Decoupled backend architecture using Flask, allowing the scanner logic to be easily queried by external applications.

## 🛠️ Tech Stack
* **Backend:** Python 3, Flask
* **Frontend:** HTML5, CSS3, Vanilla JavaScript
* **APIs & Libraries:** VirusTotal API v3, `requests`, `urllib`

## ⚙️ Prerequisites
Before you begin, ensure you have met the following requirements:
* Python 3.8+ installed on your local machine.
* A free [VirusTotal API Key](https://www.virustotal.com/gui/join-us).

## 💻 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/ThreatLens.git](https://github.com/yourusername/ThreatLens.git)
   cd ThreatLens
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables:**
   * Open `app.py` and replace `"YOUR_VIRUSTOTAL_API_KEY_HERE"` with your actual API key. 
   * *(Note: In a production environment, always use a `.env` file to manage secrets).*

5. **Run the application:**
   ```bash
   python app.py
   ```
   The application will be accessible at `http://localhost:5000`.

## 🔮 Future Enhancements
* **AI Context Analyzer:** Integrate an LLM (like the Gemini API) to analyze the semantic context of email and SMS bodies for social engineering urgency markers.
* **Exportable Reports:** Add functionality to generate and download PDF summaries of the scan results for security auditing.
* **Domain Age Verification:** Implement WHOIS lookups to flag newly registered domains, which are highly correlated with phishing campaigns.

## ⚠️ Disclaimer
This tool is built for educational and defensive purposes. It is designed to assist in identifying potential threats, but no automated tool is 100% accurate. Always exercise caution and follow organizational security policies when handling suspicious links or payloads.
```
