"""
Unit tests for core remediation agent components: Scanner, AST Engine, and Git Engine.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.scanner import BanditScanner, VulnerabilityFinding
from core.ast_engine import ASTEngine, IsolatedBlock
from core.git_engine import GitEngine


def test_bandit_scanner_finds_vulnerabilities():
    """Tests that BanditScanner detects vulnerabilities in the test target application."""
    scanner = BanditScanner()
    target_path = project_root / "test_target" / "app.py"
    findings = scanner.scan_directory(str(target_path))
    
    assert len(findings) > 0, "Bandit should detect vulnerabilities in test_target/app.py"
    test_ids = [f.test_id for f in findings]
    assert "B307" in test_ids or "B605" in test_ids, "Should detect B307 (eval) or B605 (os.system)"


def test_ast_engine_isolates_function():
    """Tests AST isolation of the calculate function containing eval."""
    target_path = project_root / "test_target" / "app.py"
    
    scanner = BanditScanner()
    findings = scanner.scan_directory(str(target_path))
    
    eval_finding = next((f for f in findings if f.test_id == "B307"), None)
    if eval_finding:
        isolated = ASTEngine.isolate_vulnerable_block(eval_finding.filename, eval_finding.line_number)
        assert isolated is not None
        assert "def calculate" in isolated.isolated_code or "eval(" in isolated.isolated_code
        assert isolated.start_line > 0


def test_git_engine_metadata_generation():
    """Tests GitEngine PR metadata creation logic."""
    git_eng = GitEngine()
    pr_meta = git_eng.create_remediation_pr(
        file_path="test_target/app.py",
        test_id="B307",
        cwe="CWE-95",
        rationale="Replaced eval with ast.literal_eval for safe math parsing.",
    )
    assert pr_meta is not None
    assert "CWE-95" in pr_meta.pr_title
    assert "B307" in pr_meta.branch_name
