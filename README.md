# IDS-Mimick
A Python-based project that mimics a real-time Intrusion Detection System by capturing and analyzing network packets. It includes a Flask-powered web interface to display potential threats and provides a manual “Analyze IP” feature to check for suspicious IP activity
 Features
- Analyze IP: Manually input any IP address to check for suspicious behavior or known threats
- Mimicks real-time packet monitoring using test packets.
- Detects suspicious patterns like DDoS,Port Scans and many more.
- Logs alerts with IP, timestamp, and threat type
- Web-based dashboard built with Flask to display live alerts


Tech Stack
Backend: Python, Flask
Network Monitoring: Scapy
Web Interface: HTML (via Flask templates)
