# ISMS Risk Management Dashboard

> Work in Progress – actively being developed

A Flask-based security dashboard that scans a target server with Nmap 
and classifies vulnerabilities based on ISO 27001 risk scoring.

## Features
- Automated Nmap scan of target server
- Risk classification based on ISO 27001 
- Risk levels: Critical, High, Medium, Low
- Status tracking: Open → In Progress → Resolved
- Live dashboard with key metrics

## Tech Stack
- Python / Flask
- Nmap / python-nmap
- Metasploitable 2 (target VM)
- HTML / CSS

## How it works
1. Start the Flask server
2. Click "View Risks"
3. Click "Scan" to scan the target
4. View discovered vulnerabilities with risk scores
5. Track remediation status per vulnerability

## Screenshot
![Dashboard](screenshot.png)

## Setup
```bash
pip install -r requirements.txt
flask run
```
