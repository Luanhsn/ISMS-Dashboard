from flask import Flask, render_template, request, redirect, url_for
import nmap
app = Flask(__name__)

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

    {
        "name": "Missing MFA",
        "description": "Multi-factor authentication is not enabled.",
        "category": "Identity Security",
        "score": 12,
        "status": "Open"
    }
]



@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/risks")
def risks():
    print(risks_data)
    return render_template("risks.html", risks=risks_data)




if __name__ == "__main__":
    app.run(debug=True)