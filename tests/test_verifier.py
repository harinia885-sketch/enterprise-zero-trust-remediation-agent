"""
Playwright E2E Browser Verification Test Suite.
Verifies target web application UI workflows post-patch.
"""

import threading
import time
import pytest
import requests
from pathlib import Path
import sys

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from test_target.app import app


@pytest.fixture(scope="module", autouse=True)
def run_test_server():
    """Spins up the test target Flask application in a background thread."""
    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)
    )
    server_thread.daemon = True
    server_thread.start()

    # Wait for server to start
    for _ in range(20):
        try:
            res = requests.get("http://127.0.0.1:5001/")
            if res.status_code == 200:
                break
        except Exception:
            time.sleep(0.2)
    yield


def test_target_app_homepage_renders():
    """Verifies that the target application homepage renders correctly."""
    response = requests.get("http://127.0.0.1:5001/")
    assert response.status_code == 200
    assert "Enterprise Target Application" in response.text


def test_calculator_business_logic():
    """Verifies calculator business logic via HTTP POST."""
    response = requests.post("http://127.0.0.1:5001/calculate", data={"expression": "10 * 5"})
    assert response.status_code == 200
    assert "50" in response.text
