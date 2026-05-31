import requests
import nmap
import os
from flask import Flask, render_template, request, redirect, url_for
from dotenv import load_dotenv
from port_knowledge import PORT_KNOWLEDGE

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()
target = os.getenv("TARGET")
nvd_api_key = os.getenv("NVD_API_KEY")

# Global in-memory list that stores all detected risks
risks_data = []


def calculate_risk_level(score):
    """Returns a risk level label based on the calculated risk score (likelihood * impact)."""
    if score >= 20:
        return "Critical"
    elif score >= 12:
        return "High"
    elif score >= 6:
        return "Medium"
    else:
        return "Low"


def get_cves(service_name):
    """Queries the NVD API for known CVEs matching the given service name. Returns up to 5 CVE IDs."""
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
            return cves[:5]
        else:
            return []
    except requests.exceptions.HTTPError:
        return []


def build_risk_entry(port, old_status, cves):
    """
    Builds a risk entry dict for a given open port.
    If the port is known in PORT_KNOWLEDGE, its metadata is used.
    Otherwise a generic 'Unknown Service' entry is created.
    The previous status is preserved from old_status if available.
    """
    if port in PORT_KNOWLEDGE:
        info = PORT_KNOWLEDGE[port]
        likelihood = info["likelihood"]
        impact = info["impact"]
        score = likelihood * impact
        entry = {
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
        }
    else:
        entry = {
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
        }

    return entry


@app.route("/")
def dashboard():
    """Renders the dashboard with a summary of risk counts by severity level."""
    total = len(risks_data)
    critical = sum(1 for r in risks_data if r["status_level"] == "Critical")
    high = sum(1 for r in risks_data if r["status_level"] == "High")
    medium = sum(1 for r in risks_data if r["status_level"] == "Medium")
    return render_template("dashboard.html", total=total, critical=critical, high=high, medium=medium)


@app.route("/risks")
def risks():
    """Renders the risks page with the full list of detected risks."""
    return render_template("risks.html", risks=risks_data)


@app.route("/scan", methods=["POST"])
def scan():
    """
    Triggers an nmap scan on the configured target.
    Preserves existing risk statuses across scans.
    Ports that are no longer detected are marked as Resolved.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sV --open")

    # Save current statuses before clearing, so they can be restored after the scan
    old_status = {}
    for r in risks_data:
        old_status[r["port"]] = r["status"]

    risks_data.clear()

    # Loop through all scan results and build a risk entry for each open port
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

                risks_data.append(build_risk_entry(port, old_status, cves))

    # Collect all ports found in this scan
    found_ports = {p["port"] for p in risks_data}

    # Mark ports from the previous scan that are no longer detected as Resolved
    for port in old_status:
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

    template = request.form.get("redirect_to")
    return redirect(url_for(template))


@app.route("/update_status/<int:index>", methods=["POST"])
def update_status(index):
    """Cycles the status of a risk entry: Open → In Progress → Resolved."""
    if risks_data[index]["status"] == "Open":
        risks_data[index]["status"] = "In Progress"
    elif risks_data[index]["status"] == "In Progress":
        risks_data[index]["status"] = "Resolved"
    return redirect(url_for("risks"))


if __name__ == "__main__":
    app.run(debug=True)
