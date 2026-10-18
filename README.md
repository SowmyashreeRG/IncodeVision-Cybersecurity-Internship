Basic Vulnerability Scanner

About the Project

This project is a Python-based Basic Vulnerability Scanner developed as part of the IncodeVision Cybersecurity Internship.

It checks a website's HTTP security headers, identifies missing security headers, checks HTTPS usage, and scans selected common ports on the local computer.

Features

- Website HTTP status checking
- HTTPS connection checking
- Security header analysis
- Detection of server information exposure
- Local port scanning
- Security findings summary by severity
- JSON report generation

Technologies Used

- Python
- Requests library
- Socket library
- JSON

Requirements

- Python 3
- Requests library

How to Run

1. Download or clone this repository.

2. Open a terminal in the project folder.

3. Install the required library:
   
   "pip install -r requirements.txt"

4. Run the scanner:
   
   "python scanner.py"

5. Enter the website URL when prompted.

Output

The scanner displays security findings in the terminal and generates a JSON report named "vulnerability_report.json".

Disclaimer

This project is intended for educational purposes. Scan only websites and systems you own or have explicit permission to test.