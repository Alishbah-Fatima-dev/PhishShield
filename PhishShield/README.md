# PhishShield
PhishShield is an AI-assisted phishing detection and threat analysis system designed to identify suspicious emails, URLs, and phishing-related content using a hybrid cybersecurity approach.

The system combines:
* Machine Learning based phishing detection
* Rule-based heuristic analysis
* Threat intelligence integration using VirusTotal
* AI-generated threat explanations
* URL and email reputation analysis

# Features
* Phishing probability scoring using Machine Learning
* Detection of credential harvesting attempts
* Threat categorization system
* VirusTotal API integration
* Email and URL parsing
* Heuristic phishing pattern detection
* AI-generated security explanations
* Risk scoring and severity classification

# Technologies Used
* Python
* Flask
* Scikit-learn
* Joblib
* VirusTotal API
* Regular Expressions (Regex)

# Current Detection Capabilities
PhishShield can currently analyze:
* Suspicious URLs
* Email addresses
* Credential phishing attempts
* Urgency and manipulation tactics
* Financial scam indicators
* Domain reputation signals

# Project Architecture
Input
→ Parsing Engine
→ Rule-Based Analysis
→ Machine Learning Detection
→ Threat Intelligence Analysis
→ AI Explanation Layer
→ Final Risk Assessment

# Example Output

Risk Score: 44.26%
Risk Level: HIGH
Threat Category: credential_harvesting

Threat Intelligence Analysis:

* Out of 92 security vendors, 0 flagged it as malicious, 0 marked it suspicious, and 63 considered it safe.

AI Analysis:
This message appears to imitate a legitimate service and attempts to steal user credentials or authentication data.

# Future Improvements
* Modern frontend dashboard
* Real-time scanning animation
* Interactive threat visualization
* Multi-API threat intelligence integration
* Advanced NLP-based phishing analysis
* Database logging system

# Disclaimer
This project is developed for educational and research purposes only.