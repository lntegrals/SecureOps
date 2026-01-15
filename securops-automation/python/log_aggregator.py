"""
Log Aggregator - Aggregates logs from multiple sources into a unified view.

This module collects and aggregates log data from various sources:
- Local log files
- Remote servers (via API or file polling)
- Cloud log services

Author: SecurOps Automation Suite
Version: 1.0.0
"""

import json
import os
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Generator, Callable, Any
from dataclasses import dataclass, asdict, field
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


@dataclass
class LogSource:
    """Configuration for a log source."""
    name: str
    source_type: str  # 'file', 'directory', 'api'
    path: str
    pattern: str = "*"
    enabled: bool = True
    poll_interval: int = 60  # seconds
    last_position: int = 0
    metadata: Dict = field(default_factory=dict)


@dataclass 
class AggregatedEntry:
    """A log entry from the aggregation system."""
    id: str
    timestamp: str
    source_name: str
    source_path: str
    level: str
    message: str
    raw: str
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class LogAggregator:
    """
    Aggregates logs from multiple sources into a unified stream.
    
    Usage:
        aggregator = LogAggregator()
        aggregator.add_source(LogSource(name="app_logs", source_type="directory", path="/var/log/app"))
        aggregator.add_source(LogSource(name="system", source_type="file", path="/var/log/syslog"))
        
        # One-time collection
        entries = aggregator.collect_all()
        
        # Or continuous monitoring
        for entry in aggregator.watch():
            process(entry)
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize the aggregator.
        
        Args:
            storage_path: Optional path to store aggregated data
        """
        self.sources: Dict[str, LogSource] = {}
        self.storage_path = storage_path
        self._stop_watching = threading.Event()
        self._entry_buffer: List[AggregatedEntry] = []
        self._buffer_lock = threading.Lock()
        
        # Statistics
        self.stats = defaultdict(lambda: {
            'entries_collected': 0,
            'bytes_processed': 0,
            'last_collection': None,
            'errors': 0
        })
        
        # Import log parser if available
        try:
            from log_parser import LogParser
            self._parser = LogParser()
        except ImportError:
            self._parser = None
    
    def add_source(self, source: LogSource):
        """Add a log source to monitor."""
        self.sources[source.name] = source
        print(f"[+] Added source: {source.name} ({source.source_type}: {source.path})")
    
    def remove_source(self, name: str):
        """Remove a log source."""
        if name in self.sources:
            del self.sources[name]
            print(f"[-] Removed source: {name}")
    
    def _generate_entry_id(self, content: str, source: str, timestamp: str) -> str:
        """Generate unique ID for a log entry."""
        hash_input = f"{content}{source}{timestamp}".encode()
        return hashlib.sha256(hash_input).hexdigest()[:16]
    
    def _parse_line(self, line: str, source: LogSource) -> Optional[AggregatedEntry]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None
        
        # Try to use the log parser if available
        if self._parser:
            # Detect format and parse
            try:
                parsed = self._parser.parse_json_log(line) or self._parser.parse_syslog(line)
                if parsed:
                    return AggregatedEntry(
                        id=self._generate_entry_id(line, source.name, parsed.timestamp),
                        timestamp=parsed.timestamp,
                        source_name=source.name,
                        source_path=source.path,
                        level=parsed.level,
                        message=parsed.message,
                        raw=line,
                        metadata=parsed.metadata
                    )
            except Exception:
                pass
        
        # Fallback: basic parsing
        return AggregatedEntry(
            id=self._generate_entry_id(line, source.name, datetime.now().isoformat()),
            timestamp=datetime.now().isoformat(),
            source_name=source.name,
            source_path=source.path,
            level="info",
            message=line,
            raw=line,
            metadata={}
        )
    
    def _read_file_incremental(self, source: LogSource) -> List[AggregatedEntry]:
        """Read new entries from a file since last position."""
        entries = []
        path = Path(source.path)
        
        if not path.exists():
            return entries
        
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                # Seek to last position
                if source.last_position > 0:
                    try:
                        f.seek(source.last_position)
                    except OSError:
                        f.seek(0)  # Reset if file was truncated
                
                for line in f:
                    entry = self._parse_line(line, source)
                    if entry:
                        entries.append(entry)
                        self.stats[source.name]['bytes_processed'] += len(line)
                
                # Update position
                source.last_position = f.tell()
                
        except Exception as e:
            self.stats[source.name]['errors'] += 1
            print(f"[ERROR] Failed to read {source.path}: {e}")
        
        return entries
    
    def _read_directory(self, source: LogSource) -> List[AggregatedEntry]:
        """Read all matching files in a directory."""
        entries = []
        path = Path(source.path)
        
        if not path.exists() or not path.is_dir():
            return entries
        
        import fnmatch
        
        for file_path in path.rglob('*'):
            if file_path.is_file() and fnmatch.fnmatch(file_path.name, source.pattern):
                file_source = LogSource(
                    name=f"{source.name}/{file_path.name}",
                    source_type='file',
                    path=str(file_path)
                )
                entries.extend(self._read_file_incremental(file_source))
        
        return entries
    
    def collect_from_source(self, source: LogSource) -> List[AggregatedEntry]:
        """Collect entries from a single source."""
        if not source.enabled:
            return []
        
        entries = []
        
        if source.source_type == 'file':
            entries = self._read_file_incremental(source)
        elif source.source_type == 'directory':
            entries = self._read_directory(source)
        elif source.source_type == 'api':
            # Placeholder for API-based log collection
            entries = self._collect_from_api(source)
        
        # Update stats
        self.stats[source.name]['entries_collected'] += len(entries)
        self.stats[source.name]['last_collection'] = datetime.now().isoformat()
        
        return entries
    
    def _collect_from_api(self, source: LogSource) -> List[AggregatedEntry]:
        """Collect logs from an API endpoint."""
        # This is a placeholder for API-based collection
        # In a real implementation, this would make HTTP requests
        entries = []
        
        api_url = source.metadata.get('api_url')
        api_key = source.metadata.get('api_key')
        
        if not api_url:
            return entries
        
        try:
            import urllib.request
            import urllib.error
            
            req = urllib.request.Request(api_url)
            if api_key:
                req.add_header('Authorization', f'Bearer {api_key}')
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                
                # Assume API returns a list of log entries
                for item in data if isinstance(data, list) else [data]:
                    entries.append(AggregatedEntry(
                        id=self._generate_entry_id(str(item), source.name, datetime.now().isoformat()),
                        timestamp=item.get('timestamp', datetime.now().isoformat()),
                        source_name=source.name,
                        source_path=api_url,
                        level=item.get('level', 'info'),
                        message=item.get('message', str(item)),
                        raw=json.dumps(item),
                        metadata=item
                    ))
                    
        except Exception as e:
            self.stats[source.name]['errors'] += 1
            print(f"[ERROR] API collection failed for {source.name}: {e}")
        
        return entries
    
    def collect_all(self, parallel: bool = True, max_workers: int = 4) -> List[AggregatedEntry]:
        """
        Collect entries from all enabled sources.
        
        Args:
            parallel: Whether to collect in parallel
            max_workers: Maximum number of parallel workers
            
        Returns:
            List of aggregated entries sorted by timestamp
        """
        all_entries = []
        
        enabled_sources = [s for s in self.sources.values() if s.enabled]
        
        if not enabled_sources:
            print("[!] No enabled sources to collect from")
            return []
        
        print(f"\n[LogAggregator] Collecting from {len(enabled_sources)} sources...")
        
        if parallel and len(enabled_sources) > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self.collect_from_source, source): source
                    for source in enabled_sources
                }
                
                for future in as_completed(futures):
                    source = futures[future]
                    try:
                        entries = future.result()
                        all_entries.extend(entries)
                        print(f"  [{source.name}] Collected {len(entries)} entries")
                    except Exception as e:
                        print(f"  [{source.name}] Error: {e}")
        else:
            for source in enabled_sources:
                entries = self.collect_from_source(source)
                all_entries.extend(entries)
                print(f"  [{source.name}] Collected {len(entries)} entries")
        
        # Sort by timestamp
        all_entries.sort(key=lambda e: e.timestamp)
        
        print(f"\n[+] Total entries collected: {len(all_entries)}")
        
        return all_entries
    
    def watch(self, callback: Optional[Callable[[AggregatedEntry], None]] = None) -> Generator[AggregatedEntry, None, None]:
        """
        Continuously watch sources and yield new entries.
        
        Args:
            callback: Optional callback function for each entry
            
        Yields:
            AggregatedEntry objects as they are collected
        """
        self._stop_watching.clear()
        print("\n[LogAggregator] Starting continuous watch...")
        
        while not self._stop_watching.is_set():
            for source in self.sources.values():
                if not source.enabled:
                    continue
                
                entries = self.collect_from_source(source)
                
                for entry in entries:
                    if callback:
                        callback(entry)
                    yield entry
            
            # Wait for next poll interval (use minimum of all sources)
            min_interval = min(
                (s.poll_interval for s in self.sources.values() if s.enabled),
                default=60
            )
            self._stop_watching.wait(min_interval)
    
    def stop_watching(self):
        """Stop the continuous watch."""
        self._stop_watching.set()
        print("[LogAggregator] Stopped watching")
    
    def get_stats(self) -> Dict:
        """Get collection statistics."""
        return {
            'sources': dict(self.stats),
            'total_entries': sum(s['entries_collected'] for s in self.stats.values()),
            'total_bytes': sum(s['bytes_processed'] for s in self.stats.values()),
            'total_errors': sum(s['errors'] for s in self.stats.values())
        }
    
    def export(self, output_path: str, entries: Optional[List[AggregatedEntry]] = None):
        """
        Export aggregated entries to JSON file.
        
        Args:
            output_path: Path to output file
            entries: Optional entries to export (collects all if not provided)
        """
        if entries is None:
            entries = self.collect_all()
        
        output = {
            'exported_at': datetime.now().isoformat(),
            'stats': self.get_stats(),
            'entries': [e.to_dict() for e in entries]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[+] Exported {len(entries)} entries to: {output_path}")
    
    def filter_entries(self, entries: List[AggregatedEntry], 
                      level: Optional[str] = None,
                      source: Optional[str] = None,
                      since: Optional[datetime] = None,
                      until: Optional[datetime] = None,
                      search: Optional[str] = None) -> List[AggregatedEntry]:
        """
        Filter entries by various criteria.
        
        Args:
            entries: List of entries to filter
            level: Filter by log level
            source: Filter by source name
            since: Filter entries after this time
            until: Filter entries before this time
            search: Search string in message
            
        Returns:
            Filtered list of entries
        """
        result = entries
        
        if level:
            result = [e for e in result if e.level.lower() == level.lower()]
        
        if source:
            result = [e for e in result if source.lower() in e.source_name.lower()]
        
        if since:
            result = [e for e in result if e.timestamp >= since.isoformat()]
        
        if until:
            result = [e for e in result if e.timestamp <= until.isoformat()]
        
        if search:
            result = [e for e in result if search.lower() in e.message.lower()]
        
        return result


def main():
    """Demo usage of LogAggregator."""
    print("\n[SecurOps] Log Aggregator")
    print("=" * 50)
    
    aggregator = LogAggregator()
    
    # Add some sample sources
    aggregator.add_source(LogSource(
        name="sample_logs",
        source_type="directory",
        path=".",
        pattern="*.log"
    ))
    
    # Collect and display
    entries = aggregator.collect_all()
    
    print(f"\nCollected {len(entries)} entries")
    print(f"Stats: {aggregator.get_stats()}")


if __name__ == "__main__":
    main()
