"""
backup_manager.py — Automated Data Backups (Industry-Grade)

Features:
  - Compresses logs, SQLite DB, and PCAPs.
  - Generates a timestamped archive.
  - Thread-safe background scheduling.
"""

import os
import time
import zipfile
import threading
from config import cfg
from app_logger import get_logger

log = get_logger(__name__)

class BackupManager:
    def __init__(self, backup_dir="backups", interval_hours=24):
        self.backup_dir = os.path.abspath(backup_dir)
        self.interval_hours = interval_hours
        self._running = False
        self._thread = None
        os.makedirs(self.backup_dir, exist_ok=True)

    def start_auto_backup(self):
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._backup_loop, daemon=True)
            self._thread.start()
            log.info(f"Automated backups started. Interval: {self.interval_hours} hours.")

    def stop(self):
        self._running = False

    def _backup_loop(self):
        while self._running:
            # Sleep in small increments to allow graceful shutdown
            for _ in range(self.interval_hours * 3600):
                if not self._running:
                    return
                time.sleep(1)
            self.create_backup()

    def create_backup(self):
        """Creates a zip archive of current logs, db, and pcaps."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(self.backup_dir, f"stealth_backup_{timestamp}.zip")
        
        targets = [
            cfg.LOG_CSV,
            cfg.LOG_CSV.replace('.csv', '.json'),
            cfg.LOG_CSV + ".pending",
            "threat_intel.db",
            "pcap_dumps"
        ]

        try:
            with zipfile.ZipFile(backup_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for target in targets:
                    if not os.path.exists(target):
                        continue
                    if os.path.isdir(target):
                        for root, _, files in os.walk(target):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, start=os.path.dirname(target))
                                zipf.write(file_path, arcname)
                    else:
                        zipf.write(target, os.path.basename(target))
            log.info(f"Backup created successfully: {backup_file}")
            return backup_file
        except Exception as e:
            log.error(f"Failed to create backup: {e}")
            return None

if __name__ == "__main__":
    bm = BackupManager()
    bm.create_backup()
