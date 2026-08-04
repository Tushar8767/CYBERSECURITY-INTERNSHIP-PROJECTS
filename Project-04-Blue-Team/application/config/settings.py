from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    root_dir: Path = Path(__file__).resolve().parents[1]
    database_path: Path = Path("rakshak_logguard.db")
    max_upload_bytes: int = 500 * 1024 * 1024
    max_archive_bytes: int = 800 * 1024 * 1024
    max_archive_files: int = 1000
    max_archive_depth: int = 2
    max_compression_ratio: float = 100.0

    @property
    def exports_dir(self) -> Path:
        return self.root_dir / "exports"

    @property
    def rules_dir(self) -> Path:
        return self.root_dir / "rules"


settings = Settings()
