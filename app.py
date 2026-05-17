import requests
from flask import Flask, render_template, request, redirect, url_for
import nmap
from dotenv import load_dotenv
import os
app = Flask(__name__)

load_dotenv()
target = os.getenv("TARGET")
nvd_api_key = os.getenv("NVD_API_KEY")

risks_data = []

PORT_KNOWLEDGE = {
    21:  {"name": "FTP",        "description": "Outdated FTP service, known backdoor in vsftpd 2.3.4",     "category": "Network",        "likelihood": 5, "impact": 5},
    22:  {"name": "SSH",        "description": "SSH exposed, weak credentials possible",                    "category": "Authentication",  "likelihood": 3, "impact": 3},
    23:  {"name": "Telnet",     "description": "Telnet transmits passwords in plaintext",                   "category": "Authentication",  "likelihood": 5, "impact": 5},
    25:  {"name": "SMTP",       "description": "Mail server exposed, relay attacks possible",               "category": "Network",        "likelihood": 3, "impact": 3},
    53:  {"name": "DNS",        "description": "DNS server exposed, zone transfer possible",                "category": "Network",        "likelihood": 2, "impact": 3},
    80:  {"name": "HTTP",       "description": "Web server running without HTTPS",                          "category": "Web Security",   "likelihood": 3, "impact": 2},
    111: {"name": "RPC",        "description": "Remote Procedure Call exposed",                             "category": "Network",        "likelihood": 3, "impact": 4},
    139: {"name": "NetBIOS",    "description": "NetBIOS exposed, information leakage possible",             "category": "Network",        "likelihood": 3, "impact": 3},
    445: {"name": "SMB",        "description": "Samba exposed, EternalBlue family applicable",              "category": "Network",        "likelihood": 4, "impact": 5},
    512: {"name": "rexec",      "description": "Remote execution without encryption",                       "category": "Authentication",  "likelihood": 5, "impact": 5},
    513: {"name": "rlogin",     "description": "Remote login without authentication possible",              "category": "Authentication",  "likelihood": 5, "impact": 5},
    1099:{"name": "RMI",        "description": "Java RMI exposed, remote code execution possible",          "category": "Network",        "likelihood": 4, "impact": 5},
    2049:{"name": "NFS",        "description": "Network file system mounted and exposed",                   "category": "Network",        "likelihood": 4, "impact": 4},
    2121:{"name": "FTP-alt",    "description": "Alternative FTP port exposed",                              "category": "Network",        "likelihood": 3, "impact": 3},
    3306:{"name": "MySQL",      "description": "Database directly reachable from outside",                  "category": "Database",       "likelihood": 4, "impact": 5},
    5432:{"name": "PostgreSQL", "description": "Database directly reachable from outside",                  "category": "Database",       "likelihood": 4, "impact": 5},
    5900:{"name": "VNC",        "description": "Remote desktop exposed, often weak password",               "category": "Remote Access",  "likelihood": 4, "impact": 5},
    6000:{"name": "X11",        "description": "X Window System exposed, GUI access possible",              "category": "Remote Access",  "likelihood": 4, "impact": 4},
    8009:{"name": "AJP",        "description": "Tomcat AJP connector exposed, Ghostcat vulnerability",      "category": "Web Security",   "likelihood": 4, "impact": 4},
    8180:{"name": "Tomcat",     "description": "Apache Tomcat Manager exposed",                             "category": "Web Security",   "likelihood": 4, "impact": 4},
}

def calculate_risk_level(score):
    if score >= 20:
        return "Critical"
    elif score >= 12:
        return "High"
    elif score >= 6:
        return "Medium"
    else:
        return "Low"



@app.route("/")
def dashboard():
    total = len(risks_data)
    critical = sum(1 for r in risks_data if r["status_level"] == "Critical")
    high = sum(1 for r in risks_data if r["status_level"] == "High")
    medium = sum(1 for r in risks_data if r["status_level"] == "Medium")
    return render_template("dashboard.html", total=total, critical=critical, high=high, medium=medium)

@app.route("/risks")
def risks():
    print(risks_data)
    return render_template("risks.html", risks=risks_data)

@app.route("/scan", methods=["POST"])
def scan():
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sV --open")

    old_status = {}
    for r in risks_data:
        old_status[r["port"]] = r["status"]

    risks_data.clear()

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]["state"]
                product = nm[host][proto][port]["product"]
                version = nm[host][proto][port]["version"]
                service_name = product + " " + version
                cves = get_cves(service_name)
                if state != "open":
                    continue

                if port in PORT_KNOWLEDGE:
                    info = PORT_KNOWLEDGE[port]
                    likelihood = info["likelihood"]
                    impact = info["impact"]
                    score = likelihood * impact
                    risks_data.append({
                        "name": info["name"],
                        "description": info["description"],
                        "category": info["category"],
                        "port": port,
                        "likelihood": likelihood,
                        "impact": impact,
                        "score": score,
                        "status_level": calculate_risk_level(score),
                        "status": old_status.get(port, "Open"),
                        "cves": cves
                    })
                else:
                    risks_data.append({
                        "name": "Unknown Service",
                        "description": f"Port {port} open – no entry in knowledge base",
                        "category": "Unknown",
                        "port": port,
                        "likelihood": 2,
                        "impact": 2,
                        "score": 4,
                        "status_level": "Low",
                        "status": old_status.get(port, "Open"),
                        "cves": []
                    })

    found_ports = {p["port"] for p in risks_data}

    for port, status in old_status.items():
        if port not in found_ports:
            risks_data.append({
                "name": PORT_KNOWLEDGE[port]["name"] if port in PORT_KNOWLEDGE else "Unknown Service",
                "description": "Port no longer detected – service closed",
                "category": PORT_KNOWLEDGE[port]["category"] if port in PORT_KNOWLEDGE else "Closed",
                "port": port,
                "likelihood": 0,
                "impact": 0,
                "score": 0,
                "status_level": "Resolved",
                "status": "Resolved"
            })

    return redirect(url_for("risks"))

@app.route("/update_status/<int:index>", methods=["POST"])
def update_status(index):
    if risks_data[index]["status"] == "Open":
        risks_data[index]["status"] = "In Progress"
    elif risks_data[index]["status"] == "In Progress":
        risks_data[index]["status"] = "Resolved"
    return redirect(url_for("risks"))

def get_cves(service_name):
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": service_name},
            headers={"apiKey": nvd_api_key},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        cves = []
        if "vulnerabilities" in data:
            for x in data["vulnerabilities"]:
                cves.append(x["cve"]["id"])
            return cves
        else:
            return []
    except requests.exceptions.HTTPError:
        return []

if __name__ == "__main__":
    app.run(debug=True)