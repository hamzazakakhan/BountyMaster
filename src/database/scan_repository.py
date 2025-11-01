"""Scan result repository for storing and retrieving scan history."""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from loguru import logger

from src.scanner.models import ScanResult
from src.config import config


class ScanRepository:
    """Repository for persisting scan results."""
    
    def __init__(self):
        self.db_path = config.cache_dir / "scans.db"
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT,
                scan_config TEXT,
                statistics TEXT,
                vulnerabilities TEXT,
                errors TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_target ON scans(target)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_started_at ON scans(started_at)
        """)
        
        conn.commit()
        conn.close()
    
    def save_scan(self, scan_result: ScanResult) -> bool:
        """Save scan result to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO scans 
                (scan_id, target, started_at, completed_at, status, 
                 scan_config, statistics, vulnerabilities, errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_result.scan_id,
                scan_result.target,
                scan_result.started_at.isoformat(),
                scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                scan_result.status,
                json.dumps(scan_result.scan_config),
                json.dumps(scan_result.statistics),
                json.dumps([v.dict() for v in scan_result.vulnerabilities], default=str),
                json.dumps(scan_result.errors)
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved scan {scan_result.scan_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error saving scan: {str(e)}")
            return False
    
    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve scan result by ID."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT scan_id, target, started_at, completed_at, status,
                       scan_config, statistics, vulnerabilities, errors
                FROM scans
                WHERE scan_id = ?
            """, (scan_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            from src.scanner.models import Vulnerability
            
            return ScanResult(
                scan_id=row[0],
                target=row[1],
                started_at=datetime.fromisoformat(row[2]),
                completed_at=datetime.fromisoformat(row[3]) if row[3] else None,
                status=row[4],
                scan_config=json.loads(row[5]),
                statistics=json.loads(row[6]),
                vulnerabilities=[Vulnerability(**v) for v in json.loads(row[7])],
                errors=json.loads(row[8])
            )
        
        except Exception as e:
            logger.error(f"Error retrieving scan: {str(e)}")
            return None
    
    def list_scans(self, limit: int = 50) -> List[dict]:
        """List recent scans."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT scan_id, target, started_at, status, statistics
                FROM scans
                ORDER BY started_at DESC
                LIMIT ?
            """, (limit,))
            
            scans = []
            for row in cursor.fetchall():
                scans.append({
                    "scan_id": row[0],
                    "target": row[1],
                    "started_at": row[2],
                    "status": row[3],
                    "statistics": json.loads(row[4])
                })
            
            conn.close()
            return scans
        
        except Exception as e:
            logger.error(f"Error listing scans: {str(e)}")
            return []
