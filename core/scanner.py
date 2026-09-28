"""
Static Vulnerability Scanner Module using Bandit.
Runs Bandit static analysis against target Python codebase and extracts structured findings.
"""

import json
import logging
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityFinding:
    """Represents a single static vulnerability finding from Bandit."""
    test_id: str
    issue_text: str
    issue_severity: str
    issue_confidence: str
    filename: str
    line_number: int
    line_range: List[int]
    code: str
    more_info: str
    cwe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BanditScanner:
    """Wrapper around Bandit static vulnerability scanner."""

    def __init__(self, severity: str = "MEDIUM", confidence: str = "MEDIUM"):
        self.severity = severity
        self.confidence = confidence

    def scan_directory(self, target_path: str) -> List[VulnerabilityFinding]:
        """
        Executes Bandit scan on target path and returns parsed findings.
        """
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(target),
            "-f",
            "json",
            "-q",
        ]

        logger.info(f"Running Bandit scan command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = result.stdout
        except Exception as e:
            logger.error(f"Failed to execute Bandit scanner: {e}")
            return []

        return self._parse_json_output(output)

    def _parse_json_output(self, json_output: str) -> List[VulnerabilityFinding]:
        """Parses raw JSON Bandit output into structured VulnerabilityFinding list."""
        findings = []
        if not json_output.strip():
            logger.warning("Bandit output empty.")
            return findings

        try:
            data = json.loads(json_output)
            results = data.get("results", [])
            for res in results:
                finding = VulnerabilityFinding(
                    test_id=res.get("test_id", ""),
                    issue_text=res.get("issue_text", ""),
                    issue_severity=res.get("issue_severity", "LOW"),
                    issue_confidence=res.get("issue_confidence", "LOW"),
                    filename=res.get("filename", ""),
                    line_number=res.get("line_number", 0),
                    line_range=res.get("line_range", []),
                    code=res.get("code", ""),
                    more_info=res.get("more_info", ""),
                    cwe=res.get("issue_cwe", {}).get("id") if isinstance(res.get("issue_cwe"), dict) else None,
                )
                findings.append(finding)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Bandit JSON output: {e}")

        return findings
