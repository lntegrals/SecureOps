"""
Log Retriever - Automated retrieval of system logs for integration health monitoring.

This module provides automated log retrieval from various sources:
- Local system logs (Windows Event Log, file-based logs)
- Remote servers via SSH/WinRM
- API endpoints
- Cloud logging services

Author: IdentityOps Automation Suite
Version: 1.0.0
"""

import json
import os
import subprocess
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from pathlib import Path
from enum import Enum
import threading
import time


class LogSourceType(Enum):
    """Types of log sources."""
    WINDOWS_EVENT = "windows_event"
    FILE = "file"
    DIRECTORY = "directory"
    API = "api"
    REMOTE = "remote"


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class LogEntry:
    """Represents a single log entry."""
    timestamp: str
    source: str
    level: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class LogSource:
    """Configuration for a log source."""
    name: str
    source_type: str
    config: Dict[str, Any]
    enabled: bool = True
    last_retrieved: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class RetrievalResult:
    """Result of a log retrieval operation."""
    source: str
    success: bool
    entries_count: int
    start_time: str
    end_time: str
    error: Optional[str] = None
    entries: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class LogRetriever:
    """
    Automated log retriever for multiple sources.
    
    Usage:
        retriever = LogRetriever()
        retriever.add_source(LogSource(
            name="app_logs",
            source_type="directory",
            config={"path": "/var/log/app", "pattern": "*.log"}
        ))
        results = retriever.retrieve_all()
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the retriever with optional configuration."""
        self.config = config or {}
        self.sources: Dict[str, LogSource] = {}
        self.results: List[RetrievalResult] = []
        self._lock = threading.Lock()
        
        # Default settings
        self.max_entries_per_source = self.config.get('max_entries_per_source', 1000)
        self.lookback_hours = self.config.get('lookback_hours', 24)
    
    def add_source(self, source: LogSource):
        """Add a log source for retrieval."""
        self.sources[source.name] = source
        print(f"[+] Added log source: {source.name} ({source.source_type})")
    
    def remove_source(self, name: str):
        """Remove a log source."""
        if name in self.sources:
            del self.sources[name]
            print(f"[-] Removed log source: {name}")
    
    def _retrieve_windows_event(self, source: LogSource) -> RetrievalResult:
        """Retrieve Windows Event Log entries."""
        start_time = datetime.now()
        entries = []
        error = None
        
        log_name = source.config.get('log_name', 'Application')
        max_events = source.config.get('max_events', self.max_entries_per_source)
        
        try:
            if platform.system() != 'Windows':
                raise NotImplementedError("Windows Event Log only available on Windows")
            
            # Use PowerShell to retrieve events
            ps_script = f'''
            $events = Get-WinEvent -LogName "{log_name}" -MaxEvents {max_events} -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, ProviderName, LevelDisplayName, Message, Id |
                ConvertTo-Json -Depth 2
            $events
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout.strip():
                raw_events = json.loads(result.stdout)
                if not isinstance(raw_events, list):
                    raw_events = [raw_events]
                
                for event in raw_events:
                    entries.append(LogEntry(
                        timestamp=event.get('TimeCreated', ''),
                        source=event.get('ProviderName', log_name),
                        level=event.get('LevelDisplayName', 'Info').lower(),
                        message=event.get('Message', '')[:500],
                        metadata={'event_id': event.get('Id')}
                    ).to_dict())
        
        except subprocess.TimeoutExpired:
            error = "Timeout retrieving Windows Event Log"
        except json.JSONDecodeError as e:
            error = f"Failed to parse event log output: {e}"
        except Exception as e:
            error = str(e)
        
        return RetrievalResult(
            source=source.name,
            success=error is None,
            entries_count=len(entries),
            start_time=start_time.isoformat(),
            end_time=datetime.now().isoformat(),
            error=error,
            entries=entries
        )
    
    def _retrieve_file(self, source: LogSource) -> RetrievalResult:
        """Retrieve logs from a file."""
        start_time = datetime.now()
        entries = []
        error = None
        
        file_path = source.config.get('path', '')
        max_lines = source.config.get('max_lines', self.max_entries_per_source)
        
        try:
            path = Path(file_path)
            
            if not path.exists():
                raise FileNotFoundError(f"Log file not found: {file_path}")
            
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                # Read last N lines
                lines = f.readlines()[-max_lines:]
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                
                # Try to parse JSON log
                try:
                    data = json.loads(line)
                    entries.append(LogEntry(
                        timestamp=data.get('timestamp', data.get('time', datetime.now().isoformat())),
                        source=data.get('source', path.name),
                        level=data.get('level', 'info').lower(),
                        message=data.get('message', line)[:500],
                        metadata=data
                    ).to_dict())
                except json.JSONDecodeError:
                    # Plain text log
                    entries.append(LogEntry(
                        timestamp=datetime.now().isoformat(),
                        source=path.name,
                        level='info',
                        message=line[:500],
                        metadata={'line_number': i + 1}
                    ).to_dict())
        
        except Exception as e:
            error = str(e)
        
        return RetrievalResult(
            source=source.name,
            success=error is None,
            entries_count=len(entries),
            start_time=start_time.isoformat(),
            end_time=datetime.now().isoformat(),
            error=error,
            entries=entries
        )
    
    def _retrieve_directory(self, source: LogSource) -> RetrievalResult:
        """Retrieve logs from all files in a directory."""
        start_time = datetime.now()
        entries = []
        error = None
        
        dir_path = source.config.get('path', '')
        pattern = source.config.get('pattern', '*.log')
        max_entries = source.config.get('max_entries', self.max_entries_per_source)
        
        try:
            path = Path(dir_path)
            
            if not path.exists() or not path.is_dir():
                raise NotADirectoryError(f"Directory not found: {dir_path}")
            
            log_files = list(path.glob(pattern))
            
            for log_file in log_files:
                if len(entries) >= max_entries:
                    break
                
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                        lines = f.readlines()[-100:]  # Last 100 lines per file
                    
                    for line in lines:
                        if len(entries) >= max_entries:
                            break
                        
                        line = line.strip()
                        if not line:
                            continue
                        
                        entries.append(LogEntry(
                            timestamp=datetime.now().isoformat(),
                            source=log_file.name,
                            level='info',
                            message=line[:500],
                            metadata={'file': str(log_file)}
                        ).to_dict())
                
                except Exception as e:
                    # Skip files that can't be read
                    pass
        
        except Exception as e:
            error = str(e)
        
        return RetrievalResult(
            source=source.name,
            success=error is None,
            entries_count=len(entries),
            start_time=start_time.isoformat(),
            end_time=datetime.now().isoformat(),
            error=error,
            entries=entries
        )
    
    def _retrieve_api(self, source: LogSource) -> RetrievalResult:
        """Retrieve logs from an API endpoint."""
        start_time = datetime.now()
        entries = []
        error = None
        
        api_url = source.config.get('url', '')
        headers = source.config.get('headers', {})
        
        try:
            import urllib.request
            import urllib.error
            
            req = urllib.request.Request(api_url)
            for key, value in headers.items():
                req.add_header(key, value)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                
                if isinstance(data, list):
                    for item in data[:self.max_entries_per_source]:
                        entries.append(LogEntry(
                            timestamp=item.get('timestamp', datetime.now().isoformat()),
                            source=item.get('source', 'api'),
                            level=item.get('level', 'info').lower(),
                            message=item.get('message', str(item))[:500],
                            metadata=item
                        ).to_dict())
                elif isinstance(data, dict):
                    logs = data.get('logs', data.get('entries', [data]))
                    for item in logs[:self.max_entries_per_source]:
                        entries.append(LogEntry(
                            timestamp=item.get('timestamp', datetime.now().isoformat()),
                            source=item.get('source', 'api'),
                            level=item.get('level', 'info').lower(),
                            message=item.get('message', str(item))[:500],
                            metadata=item
                        ).to_dict())
        
        except Exception as e:
            error = str(e)
        
        return RetrievalResult(
            source=source.name,
            success=error is None,
            entries_count=len(entries),
            start_time=start_time.isoformat(),
            end_time=datetime.now().isoformat(),
            error=error,
            entries=entries
        )
    
    def retrieve(self, source_name: str) -> RetrievalResult:
        """Retrieve logs from a specific source."""
        if source_name not in self.sources:
            return RetrievalResult(
                source=source_name,
                success=False,
                entries_count=0,
                start_time=datetime.now().isoformat(),
                end_time=datetime.now().isoformat(),
                error="Source not found"
            )
        
        source = self.sources[source_name]
        
        if not source.enabled:
            return RetrievalResult(
                source=source_name,
                success=False,
                entries_count=0,
                start_time=datetime.now().isoformat(),
                end_time=datetime.now().isoformat(),
                error="Source is disabled"
            )
        
        # Route to appropriate retriever
        if source.source_type == LogSourceType.WINDOWS_EVENT.value:
            result = self._retrieve_windows_event(source)
        elif source.source_type == LogSourceType.FILE.value:
            result = self._retrieve_file(source)
        elif source.source_type == LogSourceType.DIRECTORY.value:
            result = self._retrieve_directory(source)
        elif source.source_type == LogSourceType.API.value:
            result = self._retrieve_api(source)
        else:
            result = RetrievalResult(
                source=source_name,
                success=False,
                entries_count=0,
                start_time=datetime.now().isoformat(),
                end_time=datetime.now().isoformat(),
                error=f"Unsupported source type: {source.source_type}"
            )
        
        # Update last retrieved time
        source.last_retrieved = datetime.now().isoformat()
        
        with self._lock:
            self.results.append(result)
        
        return result
    
    def retrieve_all(self, parallel: bool = False) -> List[RetrievalResult]:
        """Retrieve logs from all enabled sources."""
        results = []
        enabled_sources = [s for s in self.sources.values() if s.enabled]
        
        print(f"\n[LogRetriever] Retrieving from {len(enabled_sources)} sources...")
        
        if parallel:
            threads = []
            thread_results = []
            
            def retrieve_threaded(source):
                result = self.retrieve(source.name)
                thread_results.append(result)
            
            for source in enabled_sources:
                t = threading.Thread(target=retrieve_threaded, args=(source,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            results = thread_results
        else:
            for source in enabled_sources:
                print(f"  Retrieving: {source.name}...")
                result = self.retrieve(source.name)
                results.append(result)
                print(f"    {'✓' if result.success else '✗'} {result.entries_count} entries")
        
        return results
    
    def get_summary(self) -> Dict:
        """Get a summary of all retrieval operations."""
        return {
            'total_sources': len(self.sources),
            'enabled_sources': len([s for s in self.sources.values() if s.enabled]),
            'total_retrievals': len(self.results),
            'successful': len([r for r in self.results if r.success]),
            'failed': len([r for r in self.results if not r.success]),
            'total_entries': sum(r.entries_count for r in self.results)
        }
    
    def export(self, output_path: str, include_entries: bool = True):
        """Export retrieval results to JSON."""
        output = {
            'exported_at': datetime.now().isoformat(),
            'summary': self.get_summary(),
            'sources': [s.to_dict() for s in self.sources.values()],
            'results': []
        }
        
        for result in self.results:
            result_dict = result.to_dict()
            if not include_entries:
                result_dict['entries'] = []
            output['results'].append(result_dict)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[+] Results exported to: {output_path}")


def main():
    """Demo usage of LogRetriever."""
    print("\n[IdentityOps] Log Retriever")
    print("=" * 50)
    
    retriever = LogRetriever()
    
    # Add sample sources
    if platform.system() == 'Windows':
        retriever.add_source(LogSource(
            name="security_events",
            source_type="windows_event",
            config={'log_name': 'Security', 'max_events': 50}
        ))
        retriever.add_source(LogSource(
            name="system_events",
            source_type="windows_event",
            config={'log_name': 'System', 'max_events': 50}
        ))
    
    # Retrieve all
    results = retriever.retrieve_all()
    
    print(f"\nSummary: {retriever.get_summary()}")
    
    # Export results
    retriever.export("./log-retrieval-results.json")


if __name__ == "__main__":
    main()
