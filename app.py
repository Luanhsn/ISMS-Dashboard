from flask import Flask, render_template

app = Flask(__name__)

risks_data = [
    {
        "name": "Brute Force Attack",
        "description": "Multiple failed SSH login attempts detected.",
        "category": "Authentication",
        "score": 20,
        "status": "Open"
    },

    {
        "name": "Weak Password Policy",
        "description": "Passwords do not meet complexity requirements.",
        "category": "Authentication",
        "score": 15,
        "status": "In Progress"
    },

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