"""
Configuration manager for Enterprise Zero-Trust Vulnerability Remediation Agent.
Loads settings from environment variables with sensible production defaults.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    """Project configuration settings."""
    
    # Base paths
    BASE_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    DATA_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "data")
    RULES_FILE: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "data" / "rules.json")
    
    # Ollama Local SLM Configuration
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "deepseek-coder:6.7b")
    OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    
    # Scanner Configuration
    BANDIT_SEVERITY_LEVEL: str = os.getenv("BANDIT_SEVERITY_LEVEL", "MEDIUM")  # LOW, MEDIUM, HIGH
    BANDIT_CONFIDENCE_LEVEL: str = os.getenv("BANDIT_CONFIDENCE_LEVEL", "MEDIUM")
    
    # Verification Configuration
    PLAYWRIGHT_HEADLESS: bool = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true"
    TEST_TARGET_PORT: int = int(os.getenv("TEST_TARGET_PORT", "5000"))
    
    # Git Configuration
    GIT_AUTHOR_NAME: str = os.getenv("GIT_AUTHOR_NAME", "ZeroTrust-Remediation-Agent")
    GIT_AUTHOR_EMAIL: str = os.getenv("GIT_AUTHOR_EMAIL", "agent@zerotrust.local")
    GIT_BRANCH_PREFIX: str = os.getenv("GIT_BRANCH_PREFIX", "fix/remediation-")


def get_config() -> Config:
    """Returns a singleton Config instance."""
    return Config()
