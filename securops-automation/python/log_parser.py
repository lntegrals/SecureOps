"""
Log Parser - Parses multiple log formats (Windows Event, syslog, JSON).

This module provides unified parsing for different log formats commonly
encountered in enterprise environments. Supports Windows Event logs,
syslog format, JSON logs, and CSV logs.

Author: SecurOps Automation Suite
Version: 1.0.0
"""

import json
import re
import csv
from datetime import datetime
from typing import Dict, List, Optional, Generator, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum


class LogFormat(Enum):
    """Supported log formats."""
    WINDOWS_EVENT = "windows_event"
    SYSLOG = "syslog"
    JSON = "json"
    CSV = "csv"
    UNKNOWN = "unknown"


@dataclass
class ParsedLogEntry:
    """Standardized log entry structure."""
    timestamp: str
    source: str
    level: str
    message: str
    raw: str
    format: str
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class LogParser:
    """
    Universal log parser supporting multiple formats.
    
    Usage:
        parser = LogParser()
        entries = parser.parse_file("path/to/logfile.log")
        for entry in entries:
            print(entry.timestamp, entry.level, entry.message)
    """
    
    # Syslog regex pattern (RFC 3164 and RFC 5424)
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*[+-]?\d{0,4})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )
    
    # Windows Event Log XML pattern
    WINDOWS_EVENT_PATTERN = re.compile(
        r'<Event.*?>.*?<TimeCreated SystemTime=["\'](?P<timestamp>[^"\']+)["\'].*?'
        r'<EventID.*?>(?P<event_id>\d+)</EventID>.*?'
        r'<Level>(?P<level>\d+)</Level>.*?'
        r'<Provider Name=["\'](?P<provider>[^"\']+)["\'].*?'
        r'(?:<Message>(?P<message>.*?)</Message>)?',
        re.DOTALL
    )
    
    # Common log level mappings
    LEVEL_MAP = {
        # Numeric levels
        '0': 'emergency',
        '1': 'alert', 
        '2': 'critical',
        '3': 'error',
        '4': 'warning',
        '5': 'notice',
        '6': 'info',
        '7': 'debug',
        # Windows event levels
        'critical': 'critical',
        'error': 'error',
        'warning': 'warning',
        'information': 'info',
        'verbose': 'debug',
    }
    
    def __init__(self):
        self.stats = {
            'total_parsed': 0,
            'by_format': {},
            'by_level': {},
            'parse_errors': 0
        }
    
    def detect_format(self, content: str) -> LogFormat:
        """Detect the log format from content sample."""
        content = content.strip()
        
        # Check for JSON
        if content.startswith('{') or content.startswith('['):
            try:
                json.loads(content)
                return LogFormat.JSON
            except json.JSONDecodeError:
                pass
        
        # Check for Windows Event XML
        if '<Event' in content and '<System>' in content:
            return LogFormat.WINDOWS_EVENT
        
        # Check for syslog format
        if self.SYSLOG_PATTERN.match(content.split('\n')[0]):
            return LogFormat.SYSLOG
        
        # Check for CSV (has commas and consistent structure)
        lines = content.split('\n')[:5]
        if all(',' in line for line in lines if line.strip()):
            return LogFormat.CSV
        
        return LogFormat.UNKNOWN
    
    def parse_syslog(self, line: str) -> Optional[ParsedLogEntry]:
        """Parse a syslog format line."""
        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Extract level from message if present
        level = 'info'
        message = groups['message']
        for level_keyword in ['error', 'warning', 'critical', 'debug', 'info']:
            if level_keyword.upper() in message[:50].upper():
                level = level_keyword
                break
        
        return ParsedLogEntry(
            timestamp=groups['timestamp'],
            source=f"{groups['host']}/{groups['process']}",
            level=level,
            message=message,
            raw=line,
            format=LogFormat.SYSLOG.value,
            metadata={
                'host': groups['host'],
                'process': groups['process'],
                'pid': groups.get('pid')
            }
        )
    
    def parse_json_log(self, line: str) -> Optional[ParsedLogEntry]:
        """Parse a JSON log line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        
        # Common JSON log field names
        timestamp_fields = ['timestamp', 'time', '@timestamp', 'datetime', 'date', 'ts']
        level_fields = ['level', 'severity', 'log_level', 'loglevel', 'lvl']
        message_fields = ['message', 'msg', 'text', 'log', 'description']
        source_fields = ['source', 'logger', 'service', 'app', 'application']
        
        def find_field(data: dict, candidates: list) -> str:
            for field in candidates:
                if field in data:
                    return str(data[field])
            return ''
        
        timestamp = find_field(data, timestamp_fields) or datetime.now().isoformat()
        level = find_field(data, level_fields).lower() or 'info'
        message = find_field(data, message_fields) or str(data)
        source = find_field(data, source_fields) or 'unknown'
        
        # Normalize level
        level = self.LEVEL_MAP.get(level, level)
        
        return ParsedLogEntry(
            timestamp=timestamp,
            source=source,
            level=level,
            message=message,
            raw=line,
            format=LogFormat.JSON.value,
            metadata=data
        )
    
    def parse_windows_event(self, content: str) -> List[ParsedLogEntry]:
        """Parse Windows Event Log XML content."""
        entries = []
        
        for match in self.WINDOWS_EVENT_PATTERN.finditer(content):
            groups = match.groupdict()
            
            # Map Windows level to standard
            level_num = groups.get('level', '6')
            level_map = {'1': 'critical', '2': 'error', '3': 'warning', '4': 'info', '5': 'debug'}
            level = level_map.get(level_num, 'info')
            
            entries.append(ParsedLogEntry(
                timestamp=groups['timestamp'],
                source=groups.get('provider', 'Windows'),
                level=level,
                message=groups.get('message', ''),
                raw=match.group(0),
                format=LogFormat.WINDOWS_EVENT.value,
                metadata={
                    'event_id': groups.get('event_id'),
                    'provider': groups.get('provider')
                }
            ))
        
        return entries
    
    def parse_csv_log(self, content: str) -> List[ParsedLogEntry]:
        """Parse CSV format logs."""
        entries = []
        lines = content.strip().split('\n')
        
        if len(lines) < 2:
            return entries
        
        # Try to detect header
        reader = csv.DictReader(lines)
        
        for row in reader:
            # Find timestamp, level, message columns
            timestamp = row.get('timestamp') or row.get('time') or row.get('date') or ''
            level = row.get('level') or row.get('severity') or 'info'
            message = row.get('message') or row.get('msg') or str(row)
            source = row.get('source') or row.get('logger') or 'csv'
            
            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                source=source,
                level=level.lower(),
                message=message,
                raw=str(row),
                format=LogFormat.CSV.value,
                metadata=dict(row)
            ))
        
        return entries
    
    def parse_file(self, filepath: str, format_hint: Optional[LogFormat] = None) -> Generator[ParsedLogEntry, None, None]:
        """
        Parse a log file and yield standardized entries.
        
        Args:
            filepath: Path to the log file
            format_hint: Optional format hint to skip auto-detection
            
        Yields:
            ParsedLogEntry objects
        """
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        # Detect format if not provided
        log_format = format_hint or self.detect_format(content)
        
        if log_format == LogFormat.WINDOWS_EVENT:
            for entry in self.parse_windows_event(content):
                self._update_stats(entry)
                yield entry
                
        elif log_format == LogFormat.CSV:
            for entry in self.parse_csv_log(content):
                self._update_stats(entry)
                yield entry
                
        else:
            # Line-by-line parsing for syslog and JSON
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                entry = None
                if log_format == LogFormat.JSON:
                    entry = self.parse_json_log(line)
                elif log_format == LogFormat.SYSLOG:
                    entry = self.parse_syslog(line)
                else:
                    # Try all parsers
                    entry = self.parse_json_log(line) or self.parse_syslog(line)
                
                if entry:
                    self._update_stats(entry)
                    yield entry
                else:
                    self.stats['parse_errors'] += 1
    
    def _update_stats(self, entry: ParsedLogEntry):
        """Update parsing statistics."""
        self.stats['total_parsed'] += 1
        self.stats['by_format'][entry.format] = self.stats['by_format'].get(entry.format, 0) + 1
        self.stats['by_level'][entry.level] = self.stats['by_level'].get(entry.level, 0) + 1
    
    def get_stats(self) -> Dict:
        """Get parsing statistics."""
        return self.stats.copy()


def parse_logs(filepath: str) -> List[Dict]:
    """
    Convenience function to parse a log file.
    
    Args:
        filepath: Path to log file
        
    Returns:
        List of parsed log entry dictionaries
    """
    parser = LogParser()
    return [entry.to_dict() for entry in parser.parse_file(filepath)]


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python log_parser.py <logfile>")
        sys.exit(1)
    
    parser = LogParser()
    
    print(f"\n[SecurOps] Log Parser")
    print("=" * 50)
    print(f"Parsing: {sys.argv[1]}\n")
    
    for entry in parser.parse_file(sys.argv[1]):
        level_colors = {
            'critical': '\033[91m',
            'error': '\033[91m',
            'warning': '\033[93m',
            'info': '\033[92m',
            'debug': '\033[90m'
        }
        reset = '\033[0m'
        color = level_colors.get(entry.level, '')
        
        print(f"{color}[{entry.level.upper():8}]{reset} {entry.timestamp} - {entry.message[:100]}")
    
    print(f"\n[Stats] {parser.get_stats()}")
