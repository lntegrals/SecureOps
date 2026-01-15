"""
Anomaly Detector - Detects unusual patterns in logs using statistical analysis.

This module analyzes log data to identify anomalies including:
- Unusual frequency patterns (sudden spikes or drops)
- Rare event detection
- Time-based anomalies (off-hours activity)
- Sequential pattern breaks

Author: SecurOps Automation Suite
Version: 1.0.0
"""

import json
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
from statistics import mean, stdev
from enum import Enum


class AnomalyType(Enum):
    """Types of anomalies that can be detected."""
    FREQUENCY_SPIKE = "frequency_spike"
    FREQUENCY_DROP = "frequency_drop"
    RARE_EVENT = "rare_event"
    OFF_HOURS = "off_hours"
    BURST_ACTIVITY = "burst_activity"
    NEW_SOURCE = "new_source"
    ERROR_SPIKE = "error_spike"


class Severity(Enum):
    """Anomaly severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_type: str
    severity: str
    timestamp: str
    description: str
    score: float
    affected_items: List[str]
    context: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class AnomalyDetector:
    """
    Statistical anomaly detector for log analysis.
    
    Usage:
        detector = AnomalyDetector()
        detector.train(historical_entries)  # Build baseline
        anomalies = detector.detect(new_entries)
        for anomaly in anomalies:
            print(f"{anomaly.severity}: {anomaly.description}")
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize detector with optional configuration.
        
        Args:
            config: Configuration dictionary with thresholds
        """
        self.config = config or {}
        
        # Detection thresholds
        self.z_score_threshold = self.config.get('z_score_threshold', 2.5)
        self.rare_event_threshold = self.config.get('rare_event_threshold', 0.01)
        self.burst_window_seconds = self.config.get('burst_window_seconds', 60)
        self.burst_threshold = self.config.get('burst_threshold', 10)
        
        # Off-hours definition (default: 10 PM - 6 AM)
        self.off_hours_start = self.config.get('off_hours_start', 22)
        self.off_hours_end = self.config.get('off_hours_end', 6)
        
        # Baseline data
        self.baseline = {
            'hourly_counts': defaultdict(list),
            'source_counts': Counter(),
            'level_counts': Counter(),
            'event_counts': Counter(),
            'total_events': 0,
            'known_sources': set(),
            'trained': False
        }
        
        self.detected_anomalies: List[Anomaly] = []
    
    def _parse_timestamp(self, timestamp: str) -> Optional[datetime]:
        """Parse various timestamp formats."""
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%b %d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp, fmt)
            except ValueError:
                continue
        
        return None
    
    def train(self, entries: List[Dict]) -> Dict:
        """
        Train the detector on historical data to establish baseline.
        
        Args:
            entries: List of log entry dictionaries with 'timestamp', 'source', 'level'
            
        Returns:
            Training statistics
        """
        print(f"\n[AnomalyDetector] Training on {len(entries)} entries...")
        
        for entry in entries:
            timestamp = self._parse_timestamp(entry.get('timestamp', ''))
            source = entry.get('source', 'unknown')
            level = entry.get('level', 'info')
            message = entry.get('message', '')
            
            self.baseline['total_events'] += 1
            self.baseline['source_counts'][source] += 1
            self.baseline['level_counts'][level] += 1
            self.baseline['known_sources'].add(source)
            
            # Track hourly patterns
            if timestamp:
                hour = timestamp.hour
                self.baseline['hourly_counts'][hour].append(1)
            
            # Track unique event patterns (first 50 chars of message)
            event_key = message[:50] if message else 'empty'
            self.baseline['event_counts'][event_key] += 1
        
        # Calculate hourly averages
        self.baseline['hourly_avg'] = {
            hour: mean(counts) if counts else 0
            for hour, counts in self.baseline['hourly_counts'].items()
        }
        
        self.baseline['trained'] = True
        
        return {
            'total_events': self.baseline['total_events'],
            'unique_sources': len(self.baseline['known_sources']),
            'level_distribution': dict(self.baseline['level_counts'])
        }
    
    def detect(self, entries: List[Dict]) -> List[Anomaly]:
        """
        Detect anomalies in new log entries.
        
        Args:
            entries: List of log entry dictionaries
            
        Returns:
            List of detected anomalies
        """
        self.detected_anomalies = []
        
        if not entries:
            return []
        
        print(f"\n[AnomalyDetector] Analyzing {len(entries)} entries...")
        
        # Run all detection methods
        self._detect_frequency_anomalies(entries)
        self._detect_rare_events(entries)
        self._detect_off_hours_activity(entries)
        self._detect_burst_activity(entries)
        self._detect_new_sources(entries)
        self._detect_error_spikes(entries)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        self.detected_anomalies.sort(
            key=lambda a: (severity_order.get(a.severity, 4), -a.score)
        )
        
        return self.detected_anomalies
    
    def _detect_frequency_anomalies(self, entries: List[Dict]):
        """Detect unusual frequency patterns."""
        if not self.baseline['trained']:
            return
        
        # Count events per hour
        hourly_counts = defaultdict(int)
        for entry in entries:
            timestamp = self._parse_timestamp(entry.get('timestamp', ''))
            if timestamp:
                hourly_counts[timestamp.hour] += 1
        
        # Compare to baseline
        for hour, count in hourly_counts.items():
            baseline_avg = self.baseline['hourly_avg'].get(hour, 0)
            
            if baseline_avg > 0:
                # Calculate z-score
                baseline_counts = self.baseline['hourly_counts'].get(hour, [1])
                if len(baseline_counts) > 1:
                    std = stdev(baseline_counts)
                    if std > 0:
                        z_score = (count - baseline_avg) / std
                        
                        if abs(z_score) > self.z_score_threshold:
                            anomaly_type = (AnomalyType.FREQUENCY_SPIKE if z_score > 0 
                                          else AnomalyType.FREQUENCY_DROP)
                            severity = self._calculate_severity(abs(z_score), 2.5, 3.5, 4.5)
                            
                            self.detected_anomalies.append(Anomaly(
                                anomaly_type=anomaly_type.value,
                                severity=severity.value,
                                timestamp=datetime.now().isoformat(),
                                description=f"{'Spike' if z_score > 0 else 'Drop'} in event frequency at hour {hour}: {count} events (baseline: {baseline_avg:.1f})",
                                score=abs(z_score),
                                affected_items=[f"hour_{hour}"],
                                context={
                                    'hour': hour,
                                    'count': count,
                                    'baseline_avg': baseline_avg,
                                    'z_score': z_score
                                }
                            ))
    
    def _detect_rare_events(self, entries: List[Dict]):
        """Detect rare or unusual events."""
        if not self.baseline['trained'] or self.baseline['total_events'] == 0:
            return
        
        event_counts = Counter()
        for entry in entries:
            message = entry.get('message', '')[:50]
            event_counts[message] += 1
        
        for event_key, count in event_counts.items():
            baseline_freq = (self.baseline['event_counts'].get(event_key, 0) / 
                           max(self.baseline['total_events'], 1))
            
            if baseline_freq < self.rare_event_threshold and count >= 3:
                self.detected_anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.RARE_EVENT.value,
                    severity=Severity.MEDIUM.value,
                    timestamp=datetime.now().isoformat(),
                    description=f"Rare event detected ({count} occurrences): {event_key}...",
                    score=1.0 - baseline_freq,
                    affected_items=[event_key],
                    context={
                        'event_pattern': event_key,
                        'count': count,
                        'baseline_frequency': baseline_freq
                    }
                ))
    
    def _detect_off_hours_activity(self, entries: List[Dict]):
        """Detect significant activity during off-hours."""
        off_hours_entries = []
        
        for entry in entries:
            timestamp = self._parse_timestamp(entry.get('timestamp', ''))
            if timestamp:
                hour = timestamp.hour
                is_off_hours = (hour >= self.off_hours_start or 
                              hour < self.off_hours_end)
                if is_off_hours:
                    off_hours_entries.append(entry)
        
        if len(off_hours_entries) >= 5:
            # Check for high-severity events during off-hours
            high_severity = [e for e in off_hours_entries 
                           if e.get('level') in ['error', 'critical', 'warning']]
            
            if high_severity:
                severity = (Severity.HIGH if len(high_severity) > 10 
                          else Severity.MEDIUM)
                
                self.detected_anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.OFF_HOURS.value,
                    severity=severity.value,
                    timestamp=datetime.now().isoformat(),
                    description=f"Significant off-hours activity: {len(off_hours_entries)} events ({len(high_severity)} warnings/errors)",
                    score=len(off_hours_entries) / max(len(entries), 1),
                    affected_items=[e.get('source', 'unknown') for e in high_severity[:5]],
                    context={
                        'total_off_hours': len(off_hours_entries),
                        'high_severity_count': len(high_severity),
                        'off_hours_range': f"{self.off_hours_start}:00 - {self.off_hours_end}:00"
                    }
                ))
    
    def _detect_burst_activity(self, entries: List[Dict]):
        """Detect burst activity patterns."""
        # Group entries by time windows
        timestamps = []
        for entry in entries:
            ts = self._parse_timestamp(entry.get('timestamp', ''))
            if ts:
                timestamps.append(ts)
        
        if len(timestamps) < 2:
            return
        
        timestamps.sort()
        
        # Detect bursts using sliding window
        burst_windows = []
        for i, ts in enumerate(timestamps):
            window_end = ts + timedelta(seconds=self.burst_window_seconds)
            window_entries = sum(1 for t in timestamps[i:] if t <= window_end)
            
            if window_entries >= self.burst_threshold:
                burst_windows.append((ts, window_entries))
        
        if burst_windows:
            max_burst = max(burst_windows, key=lambda x: x[1])
            severity = self._calculate_severity(max_burst[1], 10, 50, 100)
            
            self.detected_anomalies.append(Anomaly(
                anomaly_type=AnomalyType.BURST_ACTIVITY.value,
                severity=severity.value,
                timestamp=max_burst[0].isoformat(),
                description=f"Burst activity detected: {max_burst[1]} events within {self.burst_window_seconds} seconds",
                score=max_burst[1] / self.burst_threshold,
                affected_items=[f"window_{max_burst[0].isoformat()}"],
                context={
                    'burst_count': max_burst[1],
                    'window_seconds': self.burst_window_seconds,
                    'total_bursts': len(burst_windows)
                }
            ))
    
    def _detect_new_sources(self, entries: List[Dict]):
        """Detect events from new/unknown sources."""
        if not self.baseline['trained']:
            return
        
        new_sources = defaultdict(list)
        
        for entry in entries:
            source = entry.get('source', 'unknown')
            if source not in self.baseline['known_sources']:
                new_sources[source].append(entry)
        
        for source, source_entries in new_sources.items():
            if len(source_entries) >= 3:
                self.detected_anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.NEW_SOURCE.value,
                    severity=Severity.MEDIUM.value,
                    timestamp=datetime.now().isoformat(),
                    description=f"New source detected: '{source}' with {len(source_entries)} events",
                    score=len(source_entries),
                    affected_items=[source],
                    context={
                        'source': source,
                        'event_count': len(source_entries),
                        'sample_message': source_entries[0].get('message', '')[:100]
                    }
                ))
    
    def _detect_error_spikes(self, entries: List[Dict]):
        """Detect sudden increase in errors."""
        error_levels = ['error', 'critical', 'alert', 'emergency']
        
        error_entries = [e for e in entries 
                        if e.get('level', '').lower() in error_levels]
        
        if not error_entries:
            return
        
        error_rate = len(error_entries) / max(len(entries), 1)
        
        if self.baseline['trained']:
            baseline_error_rate = (
                sum(self.baseline['level_counts'].get(level, 0) for level in error_levels) /
                max(self.baseline['total_events'], 1)
            )
            
            if error_rate > baseline_error_rate * 2:  # Double the normal error rate
                severity = self._calculate_severity(
                    error_rate / max(baseline_error_rate, 0.01), 
                    2, 5, 10
                )
                
                self.detected_anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.ERROR_SPIKE.value,
                    severity=severity.value,
                    timestamp=datetime.now().isoformat(),
                    description=f"Error spike detected: {error_rate*100:.1f}% error rate (baseline: {baseline_error_rate*100:.1f}%)",
                    score=error_rate / max(baseline_error_rate, 0.01),
                    affected_items=[e.get('source', 'unknown') for e in error_entries[:5]],
                    context={
                        'error_count': len(error_entries),
                        'total_entries': len(entries),
                        'error_rate': error_rate,
                        'baseline_rate': baseline_error_rate
                    }
                ))
        elif error_rate > 0.2:  # More than 20% errors without baseline
            self.detected_anomalies.append(Anomaly(
                anomaly_type=AnomalyType.ERROR_SPIKE.value,
                severity=Severity.HIGH.value,
                timestamp=datetime.now().isoformat(),
                description=f"High error rate detected: {error_rate*100:.1f}% ({len(error_entries)} errors)",
                score=error_rate,
                affected_items=[e.get('source', 'unknown') for e in error_entries[:5]],
                context={
                    'error_count': len(error_entries),
                    'total_entries': len(entries),
                    'error_rate': error_rate
                }
            ))
    
    def _calculate_severity(self, value: float, low_thresh: float, 
                          med_thresh: float, high_thresh: float) -> Severity:
        """Calculate severity based on thresholds."""
        if value >= high_thresh:
            return Severity.CRITICAL
        elif value >= med_thresh:
            return Severity.HIGH
        elif value >= low_thresh:
            return Severity.MEDIUM
        return Severity.LOW
    
    def get_summary(self) -> Dict:
        """Get anomaly detection summary."""
        return {
            'total_anomalies': len(self.detected_anomalies),
            'by_type': Counter(a.anomaly_type for a in self.detected_anomalies),
            'by_severity': Counter(a.severity for a in self.detected_anomalies),
            'top_scores': [
                {'type': a.anomaly_type, 'score': a.score, 'description': a.description}
                for a in sorted(self.detected_anomalies, key=lambda x: -x.score)[:5]
            ]
        }
    
    def export_results(self, filepath: str):
        """Export anomalies to JSON file."""
        output = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_summary(),
            'anomalies': [a.to_dict() for a in self.detected_anomalies]
        }
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[+] Results exported to: {filepath}")


if __name__ == "__main__":
    # Demo usage
    print("\n[SecurOps] Anomaly Detector Demo")
    print("=" * 50)
    
    # Sample historical data for training
    historical = [
        {'timestamp': '2024-01-15T10:00:00', 'source': 'app1', 'level': 'info', 'message': 'Normal operation'},
        {'timestamp': '2024-01-15T11:00:00', 'source': 'app1', 'level': 'info', 'message': 'Normal operation'},
        {'timestamp': '2024-01-15T12:00:00', 'source': 'app2', 'level': 'warning', 'message': 'Minor issue'},
    ] * 100  # Repeat to build baseline
    
    # Sample new data with anomalies
    new_data = [
        {'timestamp': '2024-01-16T03:00:00', 'source': 'app1', 'level': 'error', 'message': 'Critical failure'},
        {'timestamp': '2024-01-16T03:00:01', 'source': 'app1', 'level': 'error', 'message': 'Critical failure'},
        {'timestamp': '2024-01-16T03:00:02', 'source': 'unknown_app', 'level': 'error', 'message': 'Unknown source'},
    ] * 20
    
    detector = AnomalyDetector()
    detector.train(historical)
    anomalies = detector.detect(new_data)
    
    print(f"\nDetected {len(anomalies)} anomalies:")
    for anomaly in anomalies:
        print(f"  [{anomaly.severity.upper()}] {anomaly.anomaly_type}: {anomaly.description}")
    
    print(f"\n[Summary] {detector.get_summary()}")
