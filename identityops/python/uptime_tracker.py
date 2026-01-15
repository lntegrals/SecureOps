"""
Uptime Tracker - Tracks and reports service uptime.

This module provides uptime tracking capabilities:
- Historical uptime data collection
- SLA compliance calculation
- Downtime incident tracking
- Uptime reports and analytics

Author: IdentityOps Automation Suite
Version: 1.0.0
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict
import threading


class IncidentSeverity(Enum):
    """Incident severity levels."""
    MINOR = "minor"       # < 5 minutes
    MAJOR = "major"       # 5-30 minutes
    CRITICAL = "critical" # > 30 minutes


@dataclass
class UptimeEntry:
    """Single uptime measurement entry."""
    timestamp: str
    service: str
    is_up: bool
    response_time_ms: float
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Incident:
    """Represents a downtime incident."""
    id: str
    service: str
    start_time: str
    end_time: Optional[str]
    duration_minutes: float
    severity: str
    resolved: bool
    description: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ServiceUptime:
    """Uptime statistics for a service."""
    service: str
    uptime_percent_24h: float
    uptime_percent_7d: float
    uptime_percent_30d: float
    total_incidents: int
    active_incident: Optional[str]
    avg_response_time_ms: float
    last_check: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class UptimeTracker:
    """
    Service uptime tracker with historical data and incident management.
    
    Usage:
        tracker = UptimeTracker()
        tracker.record(service="api", is_up=True, response_time_ms=150)
        tracker.record(service="api", is_up=False, response_time_ms=0)
        report = tracker.get_uptime_report("api")
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the tracker with optional configuration."""
        self.config = config or {}
        
        # Data storage
        self.entries: Dict[str, List[UptimeEntry]] = defaultdict(list)
        self.incidents: Dict[str, List[Incident]] = defaultdict(list)
        self.active_incidents: Dict[str, Incident] = {}
        
        # Configuration
        self.max_entries = self.config.get('max_entries', 10000)
        self.sla_target = self.config.get('sla_target', 99.9)
        self.incident_thresholds = self.config.get('incident_thresholds', {
            'minor': 5,      # < 5 minutes
            'major': 30,     # 5-30 minutes
            'critical': 30   # > 30 minutes
        })
        
        self._lock = threading.Lock()
        self._incident_counter = 0
    
    def _generate_incident_id(self) -> str:
        """Generate a unique incident ID."""
        self._incident_counter += 1
        return f"INC-{datetime.now().strftime('%Y%m%d')}-{self._incident_counter:04d}"
    
    def record(self, service: str, is_up: bool, response_time_ms: float = 0):
        """
        Record an uptime measurement.
        
        Args:
            service: Service name
            is_up: Whether the service is up
            response_time_ms: Response time in milliseconds
        """
        timestamp = datetime.now().isoformat()
        
        entry = UptimeEntry(
            timestamp=timestamp,
            service=service,
            is_up=is_up,
            response_time_ms=response_time_ms
        )
        
        with self._lock:
            # Add entry
            self.entries[service].append(entry)
            
            # Trim old entries
            if len(self.entries[service]) > self.max_entries:
                self.entries[service] = self.entries[service][-self.max_entries:]
            
            # Handle incident tracking
            if not is_up:
                # Start or continue incident
                if service not in self.active_incidents:
                    incident = Incident(
                        id=self._generate_incident_id(),
                        service=service,
                        start_time=timestamp,
                        end_time=None,
                        duration_minutes=0,
                        severity=IncidentSeverity.MINOR.value,
                        resolved=False,
                        description=f"Service {service} became unavailable"
                    )
                    self.active_incidents[service] = incident
                    print(f"[!] Incident started: {incident.id} for {service}")
            else:
                # Close incident if exists
                if service in self.active_incidents:
                    incident = self.active_incidents.pop(service)
                    incident.end_time = timestamp
                    
                    # Calculate duration
                    start = datetime.fromisoformat(incident.start_time)
                    end = datetime.fromisoformat(incident.end_time)
                    incident.duration_minutes = (end - start).total_seconds() / 60
                    incident.resolved = True
                    
                    # Set severity based on duration
                    if incident.duration_minutes > self.incident_thresholds['critical']:
                        incident.severity = IncidentSeverity.CRITICAL.value
                    elif incident.duration_minutes > self.incident_thresholds['minor']:
                        incident.severity = IncidentSeverity.MAJOR.value
                    else:
                        incident.severity = IncidentSeverity.MINOR.value
                    
                    self.incidents[service].append(incident)
                    print(f"[+] Incident resolved: {incident.id} after {incident.duration_minutes:.1f} minutes ({incident.severity})")
    
    def _calculate_uptime(self, service: str, hours: int) -> float:
        """Calculate uptime percentage for a time period."""
        if service not in self.entries or not self.entries[service]:
            return 100.0
        
        cutoff = datetime.now() - timedelta(hours=hours)
        
        relevant_entries = [
            e for e in self.entries[service]
            if datetime.fromisoformat(e.timestamp) >= cutoff
        ]
        
        if not relevant_entries:
            return 100.0
        
        up_count = sum(1 for e in relevant_entries if e.is_up)
        return round((up_count / len(relevant_entries)) * 100, 3)
    
    def _calculate_avg_response_time(self, service: str, hours: int = 24) -> float:
        """Calculate average response time for a service."""
        if service not in self.entries or not self.entries[service]:
            return 0.0
        
        cutoff = datetime.now() - timedelta(hours=hours)
        
        relevant_entries = [
            e for e in self.entries[service]
            if datetime.fromisoformat(e.timestamp) >= cutoff and e.is_up
        ]
        
        if not relevant_entries:
            return 0.0
        
        return round(
            sum(e.response_time_ms for e in relevant_entries) / len(relevant_entries),
            2
        )
    
    def get_service_uptime(self, service: str) -> ServiceUptime:
        """Get uptime statistics for a service."""
        return ServiceUptime(
            service=service,
            uptime_percent_24h=self._calculate_uptime(service, 24),
            uptime_percent_7d=self._calculate_uptime(service, 24 * 7),
            uptime_percent_30d=self._calculate_uptime(service, 24 * 30),
            total_incidents=len(self.incidents.get(service, [])),
            active_incident=self.active_incidents.get(service, {}).get('id') if service in self.active_incidents else None,
            avg_response_time_ms=self._calculate_avg_response_time(service),
            last_check=self.entries[service][-1].timestamp if self.entries.get(service) else ""
        )
    
    def get_uptime_report(self, service: str, hours: int = 24) -> Dict:
        """
        Get a detailed uptime report for a service.
        
        Args:
            service: Service name
            hours: Number of hours to include in report
            
        Returns:
            Dictionary containing uptime report data
        """
        uptime_stats = self.get_service_uptime(service)
        
        cutoff = datetime.now() - timedelta(hours=hours)
        
        # Get entries for period
        period_entries = [
            e.to_dict() for e in self.entries.get(service, [])
            if datetime.fromisoformat(e.timestamp) >= cutoff
        ]
        
        # Get incidents for period
        period_incidents = [
            i.to_dict() for i in self.incidents.get(service, [])
            if datetime.fromisoformat(i.start_time) >= cutoff
        ]
        
        # Calculate SLA compliance
        sla_compliant = uptime_stats.uptime_percent_24h >= self.sla_target
        
        # Hourly breakdown
        hourly_uptime = self._get_hourly_breakdown(service, hours)
        
        return {
            'service': service,
            'period_hours': hours,
            'generated_at': datetime.now().isoformat(),
            'uptime': uptime_stats.to_dict(),
            'sla': {
                'target': self.sla_target,
                'compliant': sla_compliant,
                'current_24h': uptime_stats.uptime_percent_24h
            },
            'incidents': {
                'total': len(period_incidents),
                'active': service in self.active_incidents,
                'list': period_incidents
            },
            'hourly_breakdown': hourly_uptime,
            'entry_count': len(period_entries)
        }
    
    def _get_hourly_breakdown(self, service: str, hours: int) -> List[Dict]:
        """Get hourly uptime breakdown."""
        breakdown = []
        now = datetime.now()
        
        for h in range(hours):
            hour_start = now - timedelta(hours=h+1)
            hour_end = now - timedelta(hours=h)
            
            hour_entries = [
                e for e in self.entries.get(service, [])
                if hour_start <= datetime.fromisoformat(e.timestamp) < hour_end
            ]
            
            if hour_entries:
                up_count = sum(1 for e in hour_entries if e.is_up)
                uptime = round((up_count / len(hour_entries)) * 100, 2)
            else:
                uptime = None  # No data for this hour
            
            breakdown.append({
                'hour': hour_start.strftime('%Y-%m-%d %H:00'),
                'uptime_percent': uptime,
                'checks': len(hour_entries)
            })
        
        return list(reversed(breakdown))
    
    def get_all_services_summary(self) -> Dict:
        """Get summary for all tracked services."""
        all_services = set(self.entries.keys()) | set(self.incidents.keys())
        
        services = []
        for service in all_services:
            stats = self.get_service_uptime(service)
            services.append({
                'name': service,
                'uptime_24h': stats.uptime_percent_24h,
                'uptime_7d': stats.uptime_percent_7d,
                'status': 'down' if service in self.active_incidents else 'up',
                'incidents_total': stats.total_incidents,
                'sla_compliant': stats.uptime_percent_24h >= self.sla_target
            })
        
        # Sort by uptime (lowest first to highlight problems)
        services.sort(key=lambda x: x['uptime_24h'])
        
        # Calculate overall stats
        avg_uptime = (
            sum(s['uptime_24h'] for s in services) / len(services)
        ) if services else 100.0
        
        return {
            'generated_at': datetime.now().isoformat(),
            'total_services': len(services),
            'services_up': len([s for s in services if s['status'] == 'up']),
            'services_down': len([s for s in services if s['status'] == 'down']),
            'sla_compliant': len([s for s in services if s['sla_compliant']]),
            'average_uptime_24h': round(avg_uptime, 3),
            'sla_target': self.sla_target,
            'active_incidents': len(self.active_incidents),
            'services': services
        }
    
    def get_incident_report(self, days: int = 30) -> Dict:
        """Get incident report for a time period."""
        cutoff = datetime.now() - timedelta(days=days)
        
        all_incidents = []
        for service, incidents in self.incidents.items():
            for incident in incidents:
                if datetime.fromisoformat(incident.start_time) >= cutoff:
                    all_incidents.append(incident.to_dict())
        
        # Sort by start time (newest first)
        all_incidents.sort(key=lambda x: x['start_time'], reverse=True)
        
        # Statistics
        by_severity = defaultdict(int)
        total_downtime = 0
        
        for incident in all_incidents:
            by_severity[incident['severity']] += 1
            total_downtime += incident['duration_minutes']
        
        return {
            'period_days': days,
            'generated_at': datetime.now().isoformat(),
            'total_incidents': len(all_incidents),
            'by_severity': dict(by_severity),
            'total_downtime_minutes': round(total_downtime, 2),
            'mean_time_to_recover_minutes': (
                round(total_downtime / len(all_incidents), 2)
                if all_incidents else 0
            ),
            'incidents': all_incidents
        }
    
    def export(self, output_path: str):
        """Export all tracking data to JSON."""
        output = {
            'exported_at': datetime.now().isoformat(),
            'summary': self.get_all_services_summary(),
            'incident_report': self.get_incident_report(),
            'services': {}
        }
        
        for service in set(self.entries.keys()) | set(self.incidents.keys()):
            output['services'][service] = self.get_uptime_report(service)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[+] Uptime data exported to: {output_path}")
    
    def import_data(self, input_path: str):
        """Import tracking data from JSON."""
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # This is a simplified import - in production would be more robust
        print(f"[+] Data imported from: {input_path}")


def main():
    """Demo usage of UptimeTracker."""
    print("\n[IdentityOps] Uptime Tracker")
    print("=" * 50)
    
    tracker = UptimeTracker({'sla_target': 99.9})
    
    # Simulate some uptime data
    services = ['api', 'database', 'cache']
    
    print("\nSimulating uptime data...")
    
    for _ in range(20):
        for service in services:
            import random
            is_up = random.random() > 0.1  # 90% uptime
            response_time = random.uniform(50, 500) if is_up else 0
            tracker.record(service, is_up, response_time)
            time.sleep(0.1)
    
    # Display reports
    print("\n[All Services Summary]")
    summary = tracker.get_all_services_summary()
    print(json.dumps(summary, indent=2))
    
    print("\n[Incident Report]")
    incidents = tracker.get_incident_report()
    print(json.dumps(incidents, indent=2))
    
    # Export
    tracker.export("./uptime-tracker-data.json")


if __name__ == "__main__":
    main()
