# Enterprise Zero-Trust Vulnerability Remediation Agent

An on-premise, autonomous AI agent designed to detect security vulnerabilities (OWASP/CWE), isolate vulnerable python code via AST analysis, patch vulnerabilities via local SLM (Ollama / DeepSeek-Coder) preserving developer business logic, verify patches with Playwright E2E browser tests, and generate automated Git Pull Requests.

---

## 🏛 Architecture Pipeline

```
  [ 1. Static Analysis ] ----> Bandit Scans Source Code & Emits JSON Findings
           |
           v
  [ 2. AST Isolation ]  ----> AST Engine isolates vulnerable function/class nodes
           |
           v
  [ 3. Local SLM Patch ] ----> Ollama (DeepSeek-Coder) generates zero-trust patch
           |
           v
  [ 4. E2E Verification] ----> Playwright E2E & Pytest test sandbox runs patch checks
           |
           v
  [ 5. Git Automation ]  ----> GitEngine creates branch & opens Automated Pull Request
```

---

## 🚀 Key Modules

- **`core/scanner.py`**: Runs static vulnerability analysis using `Bandit` and parses JSON output into standard `VulnerabilityFinding` objects.
- **`core/ast_engine.py`**: Isolates code surrounding reported vulnerabilities using Python `ast` parsing.
- **`core/patcher.py`**: Queries local SLM via Ollama API (`deepseek-coder:6.7b`) with RAG rules context.
- **`core/verifier.py`**: Executes Playwright E2E browser tests and unit tests to ensure zero regressions.
- **`core/git_engine.py`**: Manages Git branches (`fix/cwe-xxx`) and automates local commit and PR creation.
- **`config/`**: Configuration management and zero-trust security prompts.
- **`data/rules.json`**: OWASP / CWE remediation guidelines database.
- **`test_target/`**: Sample web application with intentional vulnerabilities for testing.
- **`tests/`**: Unit tests and Playwright browser verification test suite.

---

## 🛠 Prerequisites & Installation

### Prerequisites
1. **Python 3.10+**
2. **Git**
3. **Ollama** installed locally and running:
   ```bash
   ollama pull deepseek-coder:6.7b
   ollama serve
   ```

### Installation Steps

```bash
# 1. Clone or navigate to the project directory
cd enterprise_zero_trust_remediation_agent

# 2. Create and activate a virtual environment
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate

# 3. Install requirements
pip install -r requirements.txt

# 4. Install Playwright browser binaries
playwright install
```

---

## 🚦 Quick Start Execution

Run the main agent runner CLI against the test target:

```bash
python app.py --target ./test_target
```

To run unit and Playwright verification tests manually:
```bash
pytest tests/
```
