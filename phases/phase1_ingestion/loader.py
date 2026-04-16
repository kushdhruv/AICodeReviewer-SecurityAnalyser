"""
Phase 1: Repository Ingestion
Industry-grade repository loader handling Git repos and ZIP files with comprehensive logging.
"""

import os
import shutil
import tempfile
import zipfile
import asyncio
from pathlib import Path
from typing import List, Optional, Union
import hashlib
from urllib.parse import urlparse
from git import GitCommandError, Repo

from utils.logger import get_logger

logger = get_logger(__name__)

class RepoLoader:
    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".ts", ".go", ".java", ".cpp", ".c", ".h", ".cs"
    }
    MAX_REPO_SIZE_MB = 500
    MAX_FILE_SIZE_MB = 50
    TIMEOUT_SECONDS = 300

    def __init__(self, workspace_path: str = "./workspace"):
        self.workspace_dir = Path(workspace_path)
        self.workspace_dir.mkdir(exist_ok=True)
        logger.info(f"Initialized RepoLoader with workspace: {self.workspace_dir.absolute()}")

    async def load(self, source: str) -> List[Path]:
        """Main entry point. Automatically detects if input is a Git URL or local folder/ZIP."""
        logger.info(f"Attempting to load source: {source}")
        
        if source.startswith("http") or source.startswith("git"):
            return await self._load_git_repo(source)
        elif source.endswith(".zip"):
            return await self._load_zip_file(Path(source))
        elif Path(source).is_dir():
            return self._extract_code_files(Path(source))
        else:
            logger.error(f"Unsupported source format: {source}")
            raise ValueError(f"Unsupported source format: {source}")

    async def _load_git_repo(self, repo_url: str) -> List[Path]:
        url_hash = hashlib.md5(repo_url.encode()).hexdigest()
        repo_path = self.workspace_dir / f"repo_{url_hash}"
        if repo_path.exists():
            logger.debug(f"Clearing existing repository path: {repo_path}")
            shutil.rmtree(repo_path)
        
        logger.info(f"Cloning Git repository: {repo_url}")
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: Repo.clone_from(repo_url, repo_path, depth=1))
            logger.info("Git clone completed successfully.")
        except GitCommandError as e:
            logger.error(f"Git clone failed: {e}")
            raise
            
        return self._extract_code_files(repo_path)

    async def _load_zip_file(self, zip_path: Path) -> List[Path]:
        path_hash = hashlib.md5(str(zip_path).encode()).hexdigest()
        extract_path = self.workspace_dir / f"zip_{path_hash}"
        logger.info(f"Extracting ZIP file to {extract_path}")
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
        except zipfile.BadZipFile as e:
            logger.error(f"Invalid ZIP file {zip_path}: {e}")
            raise
            
        return self._extract_code_files(extract_path)

    def _extract_code_files(self, repo_path: Path) -> List[Path]:
        code_files = []
        logger.info(f"Scanning directory {repo_path} for supported files...")
        
        for file_path in repo_path.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                if file_path.stat().st_size <= (self.MAX_FILE_SIZE_MB * 1024 * 1024):
                    code_files.append(file_path)
                else:
                    logger.warning(f"Skipping large file: {file_path.name}")
                    
        logger.info(f"Discovered {len(code_files)} valid code files.")
        return code_files

