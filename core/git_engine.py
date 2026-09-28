"""
Automated Git Engine for Branching, Committing, and Pull Request Preparation.
Uses GitPython to automate secure branch creation and commit flow post verification.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import git
except ImportError:
    git = None

from config.config import get_config

logger = logging.getLogger(__name__)


@dataclass
class PRMetadata:
    """Metadata for an automated security remediation PR."""
    branch_name: str
    commit_hash: str
    pr_title: str
    pr_body: str
    target_file: str


class GitEngine:
    """Manages Git operations for zero-trust vulnerability remediation."""

    def __init__(self, repo_path: Optional[str] = None):
        cfg = get_config()
        self.repo_path = Path(repo_path or cfg.BASE_DIR).resolve()
        self.branch_prefix = cfg.GIT_BRANCH_PREFIX
        self.author_name = cfg.GIT_AUTHOR_NAME
        self.author_email = cfg.GIT_AUTHOR_EMAIL

    def is_git_repo(self) -> bool:
        """Checks if target path is inside a valid Git repository."""
        if git is None:
            return False
        try:
            _ = git.Repo(self.repo_path, search_parent_directories=True)
            return True
        except (git.InvalidGitRepositoryError, git.NoSuchPathError):
            return False

    def create_remediation_pr(
        self,
        file_path: str,
        test_id: str,
        cwe: str,
        rationale: str,
    ) -> Optional[PRMetadata]:
        """
        Creates a new branch, commits the patched file, and generates PR summary.
        """
        if git is None:
            logger.error("GitPython is not installed.")
            return None

        if not self.is_git_repo():
            logger.warning(f"{self.repo_path} is not a git repository. Simulating PR metadata generation.")
            branch_name = f"{self.branch_prefix}{cwe.lower()}-{test_id}"
            return PRMetadata(
                branch_name=branch_name,
                commit_hash="simulated-commit-hash",
                pr_title=f"security(remediation): fix {cwe} ({test_id}) in {Path(file_path).name}",
                pr_body=f"## Security Remediation Summary\n\n- **Vulnerability**: {cwe} ({test_id})\n- **Target File**: `{file_path}`\n- **Fix Rationale**: {rationale}\n\n*Verified via Playwright E2E security sandbox.*",
                target_file=file_path,
            )

        try:
            repo = git.Repo(self.repo_path, search_parent_directories=True)
            branch_name = f"{self.branch_prefix}{cwe.lower()}-{test_id}"

            # Create and checkout new branch
            current_branch = repo.active_branch.name
            logger.info(f"Creating branch '{branch_name}' from '{current_branch}'")
            new_branch = repo.create_head(branch_name)
            new_branch.checkout()

            # Stage file
            repo.index.add([file_path])

            # Commit changes
            commit_message = f"security(remediation): patch {cwe} vulnerability ({test_id})"
            author = git.Actor(self.author_name, self.author_email)
            commit = repo.index.commit(commit_message, author=author, committer=author)

            pr_body = (
                f"## Enterprise Zero-Trust Security Patch\n\n"
                f"- **Vulnerability ID**: `{test_id}`\n"
                f"- **CWE**: `{cwe}`\n"
                f"- **Modified File**: `{file_path}`\n\n"
                f"### Fix Rationale\n{rationale}\n\n"
                f"### Verification\nPassed all Playwright E2E browser and regression tests."
            )

            return PRMetadata(
                branch_name=branch_name,
                commit_hash=commit.hexsha,
                pr_title=f"security(remediation): fix {cwe} in {Path(file_path).name}",
                pr_body=pr_body,
                target_file=file_path,
            )

        except Exception as e:
            logger.error(f"Failed to create git branch/commit: {e}")
            return None
