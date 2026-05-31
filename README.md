# ISMS Risk Management Dashboard


A Flask-based security dashboard that scans a target server with Nmap 
and classifies vulnerabilities based on ISO 27001 risk scoring.

## Features
- Automated Nmap scan of target server
- Risk classification based on ISO 27001 
- Risk levels: Critical, High, Medium, Low
- Status tracking: Open → In Progress → Resolved
- Live dashboard with key metrics
- CVE lookup via NVD API per discovered service


## Tech Stack
- Python / Flask
- Nmap / python-nmap
- Metasploitable 2 (target VM)
- HTML / CSS

## How it works
1. Start the Flask server
2. Click "Scan" on Dashboard or Risks page
3. Nmap scans the target server
4. Vulnerabilities are classified with risk scores
5. Track remediation status per vulnerability

## Setup

```bash
# Clone repository
git clone https://github.com/Luanhsn/ISMS-Dashboard.git
cd ISMS-Dashboard

# Install dependencies
pip install -r requirements.txt

# Start app
flask run
```

Then open your browser at: `http://localhost:5000`

<img width="2537" height="1249" alt="screenshot" src="https://github.com/user-attachments/assets/75d9cc77-10d3-4adf-98db-d4249394047c" />

<img width="1439" height="753" alt="Bildschirmfoto 2026-05-18 um 13 47 47" src="https://github.com/user-attachments/assets/bf0ccaf9-70b4-4ef1-93a9-b9133952e9eb" />


## Setup
```bash
pip install -r requirements.txt
flask run
```
