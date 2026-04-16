"""
Phase 7: Patch Application
Goal: Take the Defender's approved secure code patch and physically overwrite 
      the vulnerable code in the workspace files.
"""

import ast
import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime

from utils.logger import get_logger

logger = get_logger(__name__)


class PatchApplicator:
    """
    Safely applies LangGraph Defender patches to the original source files.
    Creates backups before overwriting and provides rollback capability.
    """

    def __init__(self, backup_dir: str = "./workspace/backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def apply_patch(
        self,
        file_path: str,
        original_code: str,
        patched_code: str,
        start_line: int,
        end_line: int,
        create_backup: bool = True,
    ) -> bool:
        """
        Replaces the vulnerable code segment in the file with the secure patch.
        
        Args:
            file_path: Path to the original source file
            original_code: The exact vulnerable code that was analyzed
            patched_code: The Defender's secure replacement code
            start_line: Starting line number (1-indexed) of the vulnerable block
            end_line: Ending line number (1-indexed) of the vulnerable block
            create_backup: Whether to create a .bak copy before modifying
            
        Returns:
            True if patch was successfully applied, False otherwise.
        """
        target = Path(file_path)

        if not target.exists():
            logger.error(f"❌ Target file does not exist: {file_path}")
            return False

        try:
            # Read the full file
            full_content = target.read_text(encoding="utf-8")
            lines = full_content.splitlines(keepends=True)

            # Validate line range
            if start_line < 1 or end_line > len(lines):
                logger.error(
                    f"❌ Line range [{start_line}-{end_line}] out of bounds "
                    f"(file has {len(lines)} lines)"
                )
                return False

            # Validate patch syntax before applying
            try:
                ast.parse(patched_code)
            except SyntaxError as e:
                logger.error(
                    f"❌ Patch has syntax errors (line {e.lineno}): {e.msg}. "
                    f"Refusing to apply broken code."
                )
                return False

            # Create backup
            if create_backup:
                self._create_backup(target)

            # Replace the vulnerable block with the patched code
            # Ensure patched_code ends with a newline for clean splicing
            if not patched_code.endswith("\n"):
                patched_code += "\n"

            new_lines = (
                lines[: start_line - 1]  # Everything before the vulnerable block
                + [patched_code]           # The secure replacement
                + lines[end_line:]         # Everything after the vulnerable block
            )

            # Write the patched file
            target.write_text("".join(new_lines), encoding="utf-8")

            logger.info(
                f"✅ Patch applied to {target.name} "
                f"(lines {start_line}-{end_line} replaced)"
            )
            return True

        except Exception as e:
            logger.error(f"❌ Failed to apply patch to {file_path}: {e}")
            return False

    def _create_backup(self, file_path: Path):
        """Creates a timestamped backup of the file before modification."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}.bak"
        backup_path = self.backup_dir / backup_name

        shutil.copy2(file_path, backup_path)
        logger.info(f"  📦 Backup saved: {backup_path}")

    def rollback(self, file_path: str) -> bool:
        """
        Restores the most recent backup for a given file.
        """
        target = Path(file_path)
        stem = target.stem

        # Find the most recent backup matching this file
        backups = sorted(
            self.backup_dir.glob(f"{stem}_*{target.suffix}.bak"),
            reverse=True,
        )

        if not backups:
            logger.warning(f"⚠️ No backups found for {target.name}")
            return False

        latest_backup = backups[0]
        shutil.copy2(latest_backup, target)
        logger.info(f"↩️ Rolled back {target.name} from {latest_backup.name}")
        return True
