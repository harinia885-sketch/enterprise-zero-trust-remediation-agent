"""
AST Engine for Code Isolation and Contextual Scoping.
Uses Python's built-in AST module to locate function/method nodes containing vulnerable line numbers.
"""

import ast
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class IsolatedBlock:
    """Represents an isolated code block (e.g. function or method) around a vulnerability."""
    file_path: str
    target_node_name: str
    node_type: str
    start_line: int
    end_line: int
    isolated_code: str
    full_source: str


class ASTNodeVisitor(ast.NodeVisitor):
    """AST Visitor to find the closest enclosing FunctionDef, AsyncFunctionDef, or ClassDef for a line."""

    def __init__(self, target_line: int):
        self.target_line = target_line
        self.enclosing_node: Optional[ast.AST] = None

    def visit(self, node: ast.AST):
        if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
            if node.lineno <= self.target_line <= node.end_lineno:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self.enclosing_node = node
        self.generic_visit(node)


class ASTEngine:
    """Isolates vulnerable code snippets into minimal self-contained functions or blocks."""

    @staticmethod
    def isolate_vulnerable_block(file_path: str, line_number: int) -> Optional[IsolatedBlock]:
        """
        Parses target file, identifies enclosing AST node for line_number,
        and returns IsolatedBlock containing code context.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            logger.error(f"Source file not found: {file_path}")
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source, filename=str(path))
            visitor = ASTNodeVisitor(target_line=line_number)
            visitor.visit(tree)

            target_node = visitor.enclosing_node
            lines = source.splitlines()

            if target_node and hasattr(target_node, "lineno") and hasattr(target_node, "end_lineno"):
                start_line = target_node.lineno
                end_line = target_node.end_lineno
                node_name = getattr(target_node, "name", "anonymous")
                node_type = type(target_node).__name__
            else:
                # Fallback: extract context lines (+-5 lines around vulnerability)
                start_line = max(1, line_number - 5)
                end_line = min(len(lines), line_number + 5)
                node_name = f"line_{line_number}_context"
                node_type = "LineContext"

            isolated_snippet = "\n".join(lines[start_line - 1 : end_line])

            return IsolatedBlock(
                file_path=str(path),
                target_node_name=node_name,
                node_type=node_type,
                start_line=start_line,
                end_line=end_line,
                isolated_code=isolated_snippet,
                full_source=source,
            )

        except Exception as e:
            logger.error(f"Error extracting AST node from {file_path} at line {line_number}: {e}")
            return None

    @staticmethod
    def apply_patch(isolated_block: IsolatedBlock, patched_code: str) -> str:
        """
        Replaces lines from start_line to end_line in full_source with patched_code.
        """
        lines = isolated_block.full_source.splitlines()
        before = lines[: isolated_block.start_line - 1]
        after = lines[isolated_block.end_line :]

        patched_lines = patched_code.splitlines()
        new_source_lines = before + patched_lines + after
        return "\n".join(new_source_lines) + "\n"
