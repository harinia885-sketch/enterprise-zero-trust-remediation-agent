"""
Enterprise Zero-Trust Vulnerability Remediation Agent - CLI Runner / Entry Point.

Pipeline Stages:
1. Static Analysis: Bandit scan target directory for security findings.
2. AST Code Isolation: Scope vulnerable code blocks using Python AST.
3. Zero-Trust SLM Patching: Query local Ollama model (DeepSeek-Coder) with RAG context.
4. E2E Verification: Run Pytest & Playwright browser test suite.
5. Automated PR: Create Git branch, commit clean fix, and generate PR metadata.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Force UTF-8 stream encoding on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from config.config import get_config
from core.scanner import BanditScanner
from core.ast_engine import ASTEngine
from core.patcher import SLMPatcher
from core.verifier import PatchVerifier
from core.git_engine import GitEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("RemediationAgent")


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Zero-Trust Vulnerability Remediation Agent CLI"
    )
    parser.add_argument(
        "--target",
        type=str,
        default="./test_target",
        help="Target directory or file to scan and remediate (default: ./test_target)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run scan and patch generation without applying changes or creating Git commits",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Ollama model name override (default: deepseek-coder:6.7b)",
    )

    args = parser.parse_args()
    cfg = get_config()
    target_dir = Path(args.target).resolve()

    logger.info("==================================================================")
    logger.info("🛡 ENTERPRISE ZERO-TRUST VULNERABILITY REMEDIATION AGENT 🛡")
    logger.info("==================================================================")
    logger.info(f"Target Directory: {target_dir}")
    logger.info(f"Local SLM Model : {args.model or cfg.OLLAMA_MODEL}")
    logger.info(f"Dry Run Mode    : {args.dry_run}")
    logger.info("------------------------------------------------------------------")

    # 1. Run Static Vulnerability Scan
    logger.info("\n🔍 Stage 1: Running Bandit Static Vulnerability Scan...")
    scanner = BanditScanner(severity=cfg.BANDIT_SEVERITY_LEVEL)
    findings = scanner.scan_directory(str(target_dir))

    if not findings:
        logger.info("✅ No vulnerabilities detected! Target codebase is secure.")
        sys.exit(0)

    logger.info(f"⚠️ Detected {len(findings)} vulnerability finding(s):")
    for idx, f in enumerate(findings, 1):
        logger.info(f"  [{idx}] {f.test_id} ({f.cwe or 'CWE-Unknown'}) in {f.filename}:{f.line_number} -> {f.issue_text}")

    # Initialize Patcher, Verifier, Git Engine
    patcher = SLMPatcher(model_name=args.model)
    verifier = PatchVerifier(test_dir="tests")
    git_eng = GitEngine(repo_path=str(target_dir))

    remediated_count = 0

    # Process each finding
    for finding in findings:
        logger.info("\n------------------------------------------------------------------")
        logger.info(f"🛠 Processing Vulnerability [{finding.test_id}] at line {finding.line_number} in {finding.filename}")

        # 2. AST Code Isolation
        logger.info("  -> Stage 2: Isolating vulnerable code block via AST...")
        isolated = ASTEngine.isolate_vulnerable_block(finding.filename, finding.line_number)
        if not isolated:
            logger.warning(f"  ❌ Failed to isolate AST block for {finding.filename}:{finding.line_number}. Skipping.")
            continue

        logger.info(f"  -> Isolated AST Node: '{isolated.target_node_name}' ({isolated.node_type}, lines {isolated.start_line}-{isolated.end_line})")

        # 3. Generate Patch via Local SLM
        logger.info("  -> Stage 3: Querying local SLM for Zero-Trust patch...")
        patch_res = patcher.generate_patch(finding, isolated)
        if not patch_res.success:
            logger.warning(f"  ❌ Patch generation failed: {patch_res.error}. Skipping.")
            continue

        logger.info(f"  -> Patch generated successfully. Rationale: {patch_res.rationale}")

        # Construct full patched file content
        patched_file_content = ASTEngine.apply_patch(isolated, patch_res.patched_code)

        if args.dry_run:
            logger.info("  -> Dry run enabled. Skipping file application & Git branch creation.")
            logger.info(f"\nProposed Patched Code:\n{patch_res.patched_code}\n")
            continue

        # Backup original content
        original_content = isolated.full_source

        # Apply Patch to file
        with open(finding.filename, "w", encoding="utf-8") as f:
            f.write(patched_file_content)
        logger.info(f"  -> Applied patch to {finding.filename}")

        # 4. Verify Patch via E2E Browser & Unit Tests
        logger.info("  -> Stage 4: Verifying patch with Playwright / Pytest sandbox...")
        verification = verifier.run_verification()

        if verification.passed:
            logger.info("  ✅ Verification PASSED! Core business logic remains functional.")
            remediated_count += 1

            # 5. Automated Git Branch & PR Metadata
            logger.info("  -> Stage 5: Generating Git branch and PR metadata...")
            pr_metadata = git_eng.create_remediation_pr(
                file_path=finding.filename,
                test_id=finding.test_id,
                cwe=finding.cwe or "CWE-SecurityFix",
                rationale=patch_res.rationale,
            )
            if pr_metadata:
                logger.info(f"  🚀 Git PR Ready: Branch '{pr_metadata.branch_name}' Title: '{pr_metadata.pr_title}'")
        else:
            logger.error(f"  ❌ Verification FAILED! Rollback applied to {finding.filename}")
            # Revert file to original
            with open(finding.filename, "w", encoding="utf-8") as f:
                f.write(original_content)

    logger.info("\n==================================================================")
    logger.info(f"🎉 Pipeline Complete! Remediated {remediated_count}/{len(findings)} vulnerability findings.")
    logger.info("==================================================================")


if __name__ == "__main__":
    main()
