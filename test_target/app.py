"""
Vulnerable Flask Web Application (Test Target).
Contains deliberate security vulnerabilities (B307 eval_used, B605 command injection) to test the remediation agent.
"""

import os
import subprocess
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Vulnerable Target App</title></head>
<body>
    <h1>Enterprise Target Application</h1>
    
    <h2>1. Calculator (Contains B307 eval vulnerability)</h2>
    <form action="/calculate" method="POST">
        <input type="text" name="expression" placeholder="e.g. 5 * 10" required />
        <button type="submit" id="calc-submit">Calculate</button>
    </form>
    {% if result is not none %}
    <p id="calc-result">Result: {{ result }}</p>
    {% endif %}

    <h2>2. System Ping (Contains B605 command injection vulnerability)</h2>
    <form action="/ping" method="POST">
        <input type="text" name="host" placeholder="127.0.0.1" required />
        <button type="submit" id="ping-submit">Ping Host</button>
    </form>
    {% if ping_output %}
    <pre id="ping-result">{{ ping_output }}</pre>
    {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE, result=None, ping_output=None)


@app.route("/calculate", methods=["POST"])
def calculate():
    expression = request.form.get("expression", "0")
    try:
        # VULNERABILITY (B307: eval_used): unsafe dynamic code evaluation
        result = eval(expression)
    except Exception as e:
        result = f"Error: {str(e)}"
    return render_template_string(HTML_TEMPLATE, result=result, ping_output=None)


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "127.0.0.1")
    try:
        # VULNERABILITY (B605: start_process_with_a_shell / B602): unsafe command string execution
        command = f"ping -c 1 {host}" if os.name != "nt" else f"ping -n 1 {host}"
        output = os.system(command)
        status_text = f"Executed ping command for host: {host} (Exit status: {output})"
    except Exception as e:
        status_text = f"Error executing ping: {str(e)}"
    return render_template_string(HTML_TEMPLATE, result=None, ping_output=status_text)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
