"""
Health Monitor Flask Backend - REST API for system health status.

This Flask application provides endpoints for:
- System health status
- Alert management
- Health check results
- Dashboard data

Author: SecurOps Automation Suite
Version: 1.0.0
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os
import subprocess
import platform
import psutil
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from enum import Enum


app = Flask(__name__)
CORS(app)


class HealthStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthCheck:
    name: str
    status: str
    message: str
    value: Optional[float]
    threshold: Optional[float]
    last_check: str
    metadata: Dict


@dataclass
class Alert:
    id: str
    timestamp: str
    severity: str
    source: str
    title: str
    message: str
    acknowledged: bool
    resolved: bool


# In-memory storage (would be replaced with database in production)
health_data = {
    'checks': {},
    'alerts': [],
    'last_update': None
}

# Configuration
CHECK_INTERVAL = 30  # seconds
THRESHOLDS = {
    'cpu_percent': {'warning': 70, 'critical': 90},
    'memory_percent': {'warning': 80, 'critical': 95},
    'disk_percent': {'warning': 80, 'critical': 95},
}


def generate_alert_id():
    """Generate unique alert ID."""
    import hashlib
    return hashlib.sha256(str(datetime.now().timestamp()).encode()).hexdigest()[:12]


def get_system_health() -> Dict[str, HealthCheck]:
    """Collect system health metrics."""
    checks = {}
    now = datetime.now().isoformat()
    
    # CPU Check
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_status = HealthStatus.HEALTHY.value
    if cpu_percent >= THRESHOLDS['cpu_percent']['critical']:
        cpu_status = HealthStatus.CRITICAL.value
    elif cpu_percent >= THRESHOLDS['cpu_percent']['warning']:
        cpu_status = HealthStatus.WARNING.value
    
    checks['cpu'] = HealthCheck(
        name="CPU Usage",
        status=cpu_status,
        message=f"CPU usage at {cpu_percent}%",
        value=cpu_percent,
        threshold=THRESHOLDS['cpu_percent']['warning'],
        last_check=now,
        metadata={'cores': psutil.cpu_count()}
    )
    
    # Memory Check
    memory = psutil.virtual_memory()
    mem_status = HealthStatus.HEALTHY.value
    if memory.percent >= THRESHOLDS['memory_percent']['critical']:
        mem_status = HealthStatus.CRITICAL.value
    elif memory.percent >= THRESHOLDS['memory_percent']['warning']:
        mem_status = HealthStatus.WARNING.value
    
    checks['memory'] = HealthCheck(
        name="Memory Usage",
        status=mem_status,
        message=f"Memory usage at {memory.percent}%",
        value=memory.percent,
        threshold=THRESHOLDS['memory_percent']['warning'],
        last_check=now,
        metadata={
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2)
        }
    )
    
    # Disk Check
    disk = psutil.disk_usage('/')
    disk_status = HealthStatus.HEALTHY.value
    if disk.percent >= THRESHOLDS['disk_percent']['critical']:
        disk_status = HealthStatus.CRITICAL.value
    elif disk.percent >= THRESHOLDS['disk_percent']['warning']:
        disk_status = HealthStatus.WARNING.value
    
    checks['disk'] = HealthCheck(
        name="Disk Usage",
        status=disk_status,
        message=f"Disk usage at {disk.percent}%",
        value=disk.percent,
        threshold=THRESHOLDS['disk_percent']['warning'],
        last_check=now,
        metadata={
            'total_gb': round(disk.total / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2)
        }
    )
    
    # Network Check (basic)
    try:
        net_io = psutil.net_io_counters()
        checks['network'] = HealthCheck(
            name="Network I/O",
            status=HealthStatus.HEALTHY.value,
            message="Network operational",
            value=None,
            threshold=None,
            last_check=now,
            metadata={
                'bytes_sent_mb': round(net_io.bytes_sent / (1024**2), 2),
                'bytes_recv_mb': round(net_io.bytes_recv / (1024**2), 2)
            }
        )
    except Exception:
        checks['network'] = HealthCheck(
            name="Network I/O",
            status=HealthStatus.UNKNOWN.value,
            message="Unable to retrieve network stats",
            value=None,
            threshold=None,
            last_check=now,
            metadata={}
        )
    
    # Process Count
    process_count = len(psutil.pids())
    checks['processes'] = HealthCheck(
        name="Process Count",
        status=HealthStatus.HEALTHY.value if process_count < 500 else HealthStatus.WARNING.value,
        message=f"{process_count} processes running",
        value=process_count,
        threshold=500,
        last_check=now,
        metadata={}
    )
    
    return checks


def create_alert_from_check(check: HealthCheck) -> Optional[Alert]:
    """Create an alert if check is in warning or critical state."""
    if check.status in [HealthStatus.WARNING.value, HealthStatus.CRITICAL.value]:
        severity = AlertSeverity.WARNING.value if check.status == HealthStatus.WARNING.value else AlertSeverity.CRITICAL.value
        
        return Alert(
            id=generate_alert_id(),
            timestamp=datetime.now().isoformat(),
            severity=severity,
            source=check.name,
            title=f"{check.name} Alert",
            message=check.message,
            acknowledged=False,
            resolved=False
        )
    return None


def background_health_check():
    """Background thread for continuous health monitoring."""
    while True:
        try:
            checks = get_system_health()
            health_data['checks'] = {k: asdict(v) for k, v in checks.items()}
            health_data['last_update'] = datetime.now().isoformat()
            
            # Create alerts for unhealthy checks
            for check in checks.values():
                alert = create_alert_from_check(check)
                if alert:
                    # Check if similar alert already exists (not resolved)
                    existing = next(
                        (a for a in health_data['alerts'] 
                         if a['source'] == alert.source and not a['resolved']),
                        None
                    )
                    if not existing:
                        health_data['alerts'].append(asdict(alert))
            
            # Keep only last 100 alerts
            health_data['alerts'] = health_data['alerts'][-100:]
            
        except Exception as e:
            print(f"Health check error: {e}")
        
        time.sleep(CHECK_INTERVAL)


# Start background health check thread
health_thread = threading.Thread(target=background_health_check, daemon=True)


@app.route('/api/health', methods=['GET'])
def get_health():
    """Get current health status."""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'checks': health_data['checks'],
        'last_update': health_data['last_update']
    })


@app.route('/api/health/summary', methods=['GET'])
def get_health_summary():
    """Get health summary."""
    checks = health_data['checks']
    
    statuses = [c['status'] for c in checks.values()]
    
    overall = HealthStatus.HEALTHY.value
    if HealthStatus.CRITICAL.value in statuses:
        overall = HealthStatus.CRITICAL.value
    elif HealthStatus.WARNING.value in statuses:
        overall = HealthStatus.WARNING.value
    
    return jsonify({
        'overall_status': overall,
        'healthy_count': statuses.count(HealthStatus.HEALTHY.value),
        'warning_count': statuses.count(HealthStatus.WARNING.value),
        'critical_count': statuses.count(HealthStatus.CRITICAL.value),
        'total_checks': len(checks),
        'last_update': health_data['last_update']
    })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get all alerts."""
    # Filter options
    severity = request.args.get('severity')
    acknowledged = request.args.get('acknowledged')
    resolved = request.args.get('resolved')
    
    alerts = health_data['alerts']
    
    if severity:
        alerts = [a for a in alerts if a['severity'] == severity]
    if acknowledged is not None:
        ack = acknowledged.lower() == 'true'
        alerts = [a for a in alerts if a['acknowledged'] == ack]
    if resolved is not None:
        res = resolved.lower() == 'true'
        alerts = [a for a in alerts if a['resolved'] == res]
    
    return jsonify({
        'alerts': alerts,
        'total': len(alerts)
    })


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    for alert in health_data['alerts']:
        if alert['id'] == alert_id:
            alert['acknowledged'] = True
            return jsonify({'status': 'ok', 'alert': alert})
    
    return jsonify({'status': 'error', 'message': 'Alert not found'}), 404


@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve an alert."""
    for alert in health_data['alerts']:
        if alert['id'] == alert_id:
            alert['resolved'] = True
            return jsonify({'status': 'ok', 'alert': alert})
    
    return jsonify({'status': 'error', 'message': 'Alert not found'}), 404


@app.route('/api/system/info', methods=['GET'])
def get_system_info():
    """Get system information."""
    return jsonify({
        'hostname': platform.node(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
    })


@app.route('/api/metrics/history', methods=['GET'])
def get_metrics_history():
    """Get historical metrics (last hour simulation)."""
    # In production, this would query a time-series database
    now = datetime.now()
    history = []
    
    for i in range(60):
        timestamp = now - timedelta(minutes=i)
        history.append({
            'timestamp': timestamp.isoformat(),
            'cpu': 30 + (i % 20),
            'memory': 45 + (i % 15),
            'disk': 60 + (i % 5)
        })
    
    return jsonify({
        'metrics': list(reversed(history)),
        'period': 'last_hour'
    })


@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_data():
    """Get all data needed for dashboard."""
    checks = health_data['checks']
    alerts = [a for a in health_data['alerts'] if not a['resolved']]
    
    statuses = [c['status'] for c in checks.values()]
    
    return jsonify({
        'health': {
            'checks': checks,
            'summary': {
                'healthy': statuses.count(HealthStatus.HEALTHY.value),
                'warning': statuses.count(HealthStatus.WARNING.value),
                'critical': statuses.count(HealthStatus.CRITICAL.value)
            }
        },
        'alerts': {
            'active': len(alerts),
            'unacknowledged': len([a for a in alerts if not a['acknowledged']]),
            'recent': alerts[:5]
        },
        'system': {
            'hostname': platform.node(),
            'uptime': str(timedelta(seconds=int(time.time() - psutil.boot_time())))
        },
        'last_update': health_data['last_update']
    })


if __name__ == '__main__':
    print("\n[SecurOps] Health Monitor API")
    print("=" * 50)
    print("Starting health monitoring...")
    
    # Start background monitoring
    health_thread.start()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
