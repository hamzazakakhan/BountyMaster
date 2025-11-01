"""Configuration management for Bug Bounty CLI."""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()


class Config(BaseModel):
    """Application configuration."""
    
    # API Keys
    openai_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    nvd_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    
    # Scan Configuration
    max_threads: int = Field(default_factory=lambda: int(os.getenv("MAX_THREADS", "10")))
    timeout_seconds: int = Field(default_factory=lambda: int(os.getenv("TIMEOUT_SECONDS", "30")))
    rate_limit_delay: float = Field(default_factory=lambda: float(os.getenv("RATE_LIMIT_DELAY", "1")))
    
    # Exploit Database Settings
    exploit_db_update_interval: int = Field(
        default_factory=lambda: int(os.getenv("EXPLOIT_DB_UPDATE_INTERVAL", "86400"))
    )
    cache_expiry_days: int = Field(default_factory=lambda: int(os.getenv("CACHE_EXPIRY_DAYS", "7")))
    
    # Logging
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_file: str = Field(default_factory=lambda: os.getenv("LOG_FILE", "bug_bounty.log"))
    
    # Directories
    base_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent)
    reports_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "reports")
    cache_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "exploits_cache")
    logs_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "logs")
    
    def __init__(self, **data):
        super().__init__(**data)
        # Create directories if they don't exist
        self.reports_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
    
    def validate_api_keys(self) -> dict[str, bool]:
        """Validate that required API keys are present."""
        return {
            "openai": bool(self.openai_api_key),
            "nvd": bool(self.nvd_api_key),
        }
    
    class Config:
        arbitrary_types_allowed = True


# Global config instance
config = Config()
