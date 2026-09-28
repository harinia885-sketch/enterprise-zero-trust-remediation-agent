"""
Patch Verification Engine using Pytest and Playwright E2E tests.
Ensures that the security patch does not break core developer business logic or introduce UI regression.
"""

import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of automated Pytest & Playwright test run."""
    passed: bool
    total_tests: int
    failed_tests: int
    output: str
    error: Optional[str] = None


class PatchVerifier:
    """Runs test suite (unit + Playwright E2E browser verification) against patched code."""

    def __init__(self, test_dir: str = "tests"):
        self.test_dir = Path(test_dir).resolve()

    def run_verification(self) -> VerificationResult:
        """
        Runs pytest test suite against project/tests.
        Returns VerificationResult with status and execution logs.
        """
        if not self.test_dir.exists():
            return VerificationResult(
                passed=False,
                total_tests=0,
                failed_tests=0,
                output="",
                error=f"Test directory {self.test_dir} does not exist.",
            )

        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(self.test_dir),
            "-v",
            "--tb=short",
        ]

        logger.info(f"Executing Playwright/Pytest verification suite: {' '.join(cmd)}")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = res.stdout + "\n" + res.stderr
            passed = (res.returncode == 0)

            return VerificationResult(
                passed=passed,
                total_tests=1,  # Simplified counter for initial runner
                failed_tests=0 if passed else 1,
                output=output,
                error=None if passed else f"Pytest exit code {res.returncode}",
            )
        except Exception as e:
            logger.error(f"Error executing verification suite: {e}")
            return VerificationResult(
                passed=False,
                total_tests=0,
                failed_tests=1,
                output="",
                error=str(e),
            )
