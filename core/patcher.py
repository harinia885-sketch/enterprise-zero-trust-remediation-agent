"""
Local SLM Security Patcher Module.
Connects to local Ollama instance (DeepSeek-Coder) to generate zero-trust security patches.
"""

import json
import logging
import requests
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional

from config.config import get_config
from config.prompts import SYSTEM_SECURITY_PROMPT, PATCH_GENERATION_PROMPT
from core.scanner import VulnerabilityFinding
from core.ast_engine import IsolatedBlock

logger = logging.getLogger(__name__)


@dataclass
class PatchResult:
    """Result of SLM patch generation attempt."""
    success: bool
    rationale: str
    patched_code: str
    raw_response: str
    error: Optional[str] = None


class SLMPatcher:
    """Interacts with Ollama local SLM to fix vulnerability without breaking business logic."""

    def __init__(self, model_name: Optional[str] = None, base_url: Optional[str] = None):
        cfg = get_config()
        self.model_name = model_name or cfg.OLLAMA_MODEL
        self.base_url = base_url or cfg.OLLAMA_BASE_URL
        self.rules = self._load_rules(cfg.RULES_FILE)

    def _load_rules(self, rules_file: Path) -> Dict[str, Any]:
        """Loads CWE/OWASP remediation rules for RAG context."""
        if rules_file.exists():
            try:
                with open(rules_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not load rules.json: {e}")
        return {}

    def generate_patch(self, finding: VulnerabilityFinding, isolated: IsolatedBlock) -> PatchResult:
        """
        Sends vulnerability finding and isolated block to Ollama for patch generation.
        """
        rule_info = self.rules.get(finding.test_id, {})
        guidance = rule_info.get("guidance", "Fix the vulnerability using safe, secure Python coding standards.")

        prompt = PATCH_GENERATION_PROMPT.format(
            test_id=finding.test_id,
            issue_text=finding.issue_text,
            severity=finding.issue_severity,
            guidance=guidance,
            file_path=finding.filename,
            line_range=str(finding.line_range),
            vulnerable_code=isolated.isolated_code,
        )

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_SECURITY_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "format": "json",
        }

        url = f"{self.base_url}/api/chat"
        logger.info(f"Querying Ollama SLM model '{self.model_name}' at {url}...")

        try:
            response = requests.post(url, json=payload, timeout=120)
            if response.status_code != 200:
                err_msg = f"Ollama HTTP {response.status_code}: {response.text}"
                logger.error(err_msg)
                return PatchResult(success=False, rationale="", patched_code="", raw_response=response.text, error=err_msg)

            res_data = response.json()
            content = res_data.get("message", {}).get("content", "")
            return self._parse_slm_json_response(content)

        except Exception as e:
            err_msg = f"Exception querying Ollama SLM: {e}"
            logger.error(err_msg)
            return PatchResult(success=False, rationale="", patched_code="", raw_response="", error=err_msg)

    def _parse_slm_json_response(self, content: str) -> PatchResult:
        """Parses structured JSON response from SLM output."""
        try:
            parsed = json.loads(content)
            rationale = parsed.get("rationale", "Patch generated.")
            patched_code = parsed.get("patched_code", "")

            # Clean markdown formatting if model accidentally wrapped output
            if patched_code.startswith("```python"):
                patched_code = patched_code.split("\n", 1)[1]
            if patched_code.endswith("```"):
                patched_code = patched_code.rsplit("```", 1)[0]
            patched_code = patched_code.strip()

            return PatchResult(
                success=bool(patched_code),
                rationale=rationale,
                patched_code=patched_code,
                raw_response=content,
            )
        except json.JSONDecodeError:
            # Fallback if raw text returned
            logger.warning("SLM did not return strict JSON. Using raw text as patched code.")
            clean_code = content.strip()
            return PatchResult(
                success=bool(clean_code),
                rationale="Raw response extracted.",
                patched_code=clean_code,
                raw_response=content,
            )
