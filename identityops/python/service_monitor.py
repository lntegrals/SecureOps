"""
Service Monitor - Monitors service health across disparate systems.

This module provides service health monitoring capabilities:
- HTTP/HTTPS endpoint health checks
- TCP port connectivity checks
- Response time tracking
- Alert generation for degraded services
- Historical health data

Author: IdentityOps Automation Suite
Version: 1.0.0
"""

import json
import socket
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ssl


class ServiceStatus(Enum):
    """Service health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class CheckType(Enum):
    """Types of health checks."""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    PING = "ping"


@dataclass
class ServiceCheck:
    """Configuration for a service health check."""
    name: str
    check_type: str
    target: str  # URL or host:port
    timeout: int = 10
    interval: int = 60
    expected_status: int = 200  # For HTTP checks
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CheckResult:
    """Result of a single health check."""
    service_name: str
    status: str
    response_time_ms: float
    timestamp: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ServiceHealth:
    """Overall health status for a service."""
    name: str
    current_status: str
    last_check: str
    uptime_percent: float
    avg_response_time_ms: float
    check_count: int
    failure_count: int
    last_failure: Optional[str] = None
    history: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ServiceMonitor:
    """
    Multi-service health monitor.
    
    Usage:
        monitor = ServiceMonitor()
        monitor.add_service(ServiceCheck(
            name="api",
            check_type="https",
            target="https://api.example.com/health"
        ))
        results = monitor.check_all()
        print(monitor.get_dashboard_data())
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the monitor with optional configuration."""
        self.config = config or {}
        self.services: Dict[str, ServiceCheck] = {}
        self.health_data: Dict[str, ServiceHealth] = {}
        self.results_history: List[CheckResult] = []
        self._lock = threading.Lock()
        self._stop_monitoring = threading.Event()
        
        # Configuration
        self.max_history = self.config.get('max_history', 1000)
        self.degraded_threshold_ms = self.config.get('degraded_threshold_ms', 2000)
        self.alert_on_failure = self.config.get('alert_on_failure', True)
        
        # Alert callbacks
        self._alert_callbacks: List[Callable[[CheckResult], None]] = []
    
    def add_service(self, service: ServiceCheck):
        """Add a service to monitor."""
        self.services[service.name] = service
        self.health_data[service.name] = ServiceHealth(
            name=service.name,
            current_status=ServiceStatus.UNKNOWN.value,
            last_check="",
            uptime_percent=100.0,
            avg_response_time_ms=0.0,
            check_count=0,
            failure_count=0,
            history=[]
        )
        print(f"[+] Added service: {service.name} ({service.check_type}://{service.target})")
    
    def remove_service(self, name: str):
        """Remove a service from monitoring."""
        if name in self.services:
            del self.services[name]
            if name in self.health_data:
                del self.health_data[name]
            print(f"[-] Removed service: {name}")
    
    def add_alert_callback(self, callback: Callable[[CheckResult], None]):
        """Add a callback function for alerts."""
        self._alert_callbacks.append(callback)
    
    def _check_http(self, service: ServiceCheck) -> CheckResult:
        """Perform an HTTP/HTTPS health check."""
        start_time = time.time()
        
        try:
            # Create request
            req = Request(
                service.target,
                headers={'User-Agent': 'IdentityOps-ServiceMonitor/1.0'}
            )
            
            # Handle HTTPS
            context = None
            if service.check_type == CheckType.HTTPS.value:
                context = ssl.create_default_context()
                # Allow self-signed certs if configured
                if service.metadata.get('allow_insecure', False):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
            
            # Make request
            response = urlopen(req, timeout=service.timeout, context=context)
            response_time = (time.time() - start_time) * 1000
            
            status_code = response.getcode()
            
            if status_code == service.expected_status:
                status = ServiceStatus.HEALTHY.value
                if response_time > self.degraded_threshold_ms:
                    status = ServiceStatus.DEGRADED.value
                message = f"HTTP {status_code} OK"
            else:
                status = ServiceStatus.DEGRADED.value
                message = f"Unexpected status: {status_code}"
            
            return CheckResult(
                service_name=service.name,
                status=status,
                response_time_ms=round(response_time, 2),
                timestamp=datetime.now().isoformat(),
                message=message,
                details={'status_code': status_code}
            )
        
        except HTTPError as e:
            response_time = (time.time() - start_time) * 1000
            return CheckResult(
                service_name=service.name,
                status=ServiceStatus.UNHEALTHY.value,
                response_time_ms=round(response_time, 2),
                timestamp=datetime.now().isoformat(),
                message=f"HTTP Error: {e.code}",
                details={'status_code': e.code, 'reason': e.reason}
            )
        
        except URLError as e:
            response_time = (time.time() - start_time) * 1000
            return CheckResult(
                service_name=service.name,
                status=ServiceStatus.UNHEALTHY.value,
                response_time_ms=round(response_time, 2),
                timestamp=datetime.now().isoformat(),
                message=f"Connection Error: {e.reason}",
                details={'error': str(e.reason)}
            )
        
        except Exception as e:
            return CheckResult(
                service_name=service.name,
                status=ServiceStatus.UNHEALTHY.value,
                response_time_ms=0,
                timestamp=datetime.now().isoformat(),
                message=f"Error: {str(e)}",
                details={'error': str(e)}
            )
    
    def _check_tcp(self, service: ServiceCheck) -> CheckResult:
        """Perform a TCP connectivity check."""
        start_time = time.time()
        
        try:
            # Parse host:port
            if ':' in service.target:
                host, port = service.target.rsplit(':', 1)
                port = int(port)
            else:
                host = service.target
                port = 80
            
            # Attempt connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(service.timeout)
            
            result = sock.connect_ex((host, port))
            response_time = (time.time() - start_time) * 1000
            sock.close()
            
            if result == 0:
                status = ServiceStatus.HEALTHY.value
                if response_time > self.degraded_threshold_ms:
                    status = ServiceStatus.DEGRADED.value
                message = f"TCP connection successful to {host}:{port}"
            else:
                status = ServiceStatus.UNHEALTHY.value
                message = f"TCP connection failed to {host}:{port}"
            
            return CheckResult(
                service_name=service.name,
                status=status,
                response_time_ms=round(response_time, 2),
                timestamp=datetime.now().isoformat(),
                message=message,
                details={'host': host, 'port': port, 'result_code': result}
            )
        
        except socket.timeout:
            return CheckResult(
                service_name=service.name,
                status=ServiceStatus.UNHEALTHY.value,
                response_time_ms=service.timeout * 1000,
                timestamp=datetime.now().isoformat(),
                message="Connection timeout",
                details={'error': 'timeout'}
            )
        
        except Exception as e:
            return CheckResult(
                service_name=service.name,
                status=ServiceStatus.UNHEALTHY.value,
                response_time_ms=0,
                timestamp=datetime.now().isoformat(),
                message=f"Error: {str(e)}",
                details={'error': str(e)}
            )
    
    def check_service(self, name: str) -> CheckResult:
        """Check a specific service."""
        if name not in self.services:
            return CheckResult(
                service_name=name,
                status=ServiceStatus.UNKNOWN.value,
                response_time_ms=0,
                timestamp=datetime.now().isoformat(),
                message="Service not found",
                details={}
            )
        
        service = self.services[name]
        
        if not service.enabled:
            return CheckResult(
                service_name=name,
                status=ServiceStatus.UNKNOWN.value,
                response_time_ms=0,
                timestamp=datetime.now().isoformat(),
                message="Service is disabled",
                details={}
            )
        
        # Route to appropriate checker
        if service.check_type in [CheckType.HTTP.value, CheckType.HTTPS.value]:
            result = self._check_http(service)
        elif service.check_type == CheckType.TCP.value:
            result = self._check_tcp(service)
        else:
            result = CheckResult(
                service_name=name,
                status=ServiceStatus.UNKNOWN.value,
                response_time_ms=0,
                timestamp=datetime.now().isoformat(),
                message=f"Unsupported check type: {service.check_type}",
                details={}
            )
        
        # Update health data
        self._update_health_data(name, result)
        
        # Trigger alerts if needed
        if result.status == ServiceStatus.UNHEALTHY.value and self.alert_on_failure:
            for callback in self._alert_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    print(f"[!] Alert callback error: {e}")
        
        return result
    
    def _update_health_data(self, name: str, result: CheckResult):
        """Update the health data for a service."""
        with self._lock:
            if name not in self.health_data:
                return
            
            health = self.health_data[name]
            health.current_status = result.status
            health.last_check = result.timestamp
            health.check_count += 1
            
            if result.status == ServiceStatus.UNHEALTHY.value:
                health.failure_count += 1
                health.last_failure = result.timestamp
            
            # Calculate uptime
            health.uptime_percent = round(
                ((health.check_count - health.failure_count) / health.check_count) * 100, 2
            )
            
            # Update average response time
            if result.response_time_ms > 0:
                total_time = health.avg_response_time_ms * (health.check_count - 1)
                health.avg_response_time_ms = round(
                    (total_time + result.response_time_ms) / health.check_count, 2
                )
            
            # Add to history
            health.history.append(result.to_dict())
            health.history = health.history[-100:]  # Keep last 100
            
            # Add to global history
            self.results_history.append(result)
            self.results_history = self.results_history[-self.max_history:]
    
    def check_all(self) -> List[CheckResult]:
        """Check all enabled services."""
        results = []
        enabled_services = [s for s in self.services.values() if s.enabled]
        
        print(f"\n[ServiceMonitor] Checking {len(enabled_services)} services...")
        
        for service in enabled_services:
            result = self.check_service(service.name)
            results.append(result)
            
            status_icon = {
                ServiceStatus.HEALTHY.value: '✓',
                ServiceStatus.DEGRADED.value: '⚠',
                ServiceStatus.UNHEALTHY.value: '✗',
                ServiceStatus.UNKNOWN.value: '?'
            }.get(result.status, '?')
            
            print(f"  {status_icon} {service.name}: {result.message} ({result.response_time_ms}ms)")
        
        return results
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring in a background thread."""
        self._stop_monitoring.clear()
        
        def monitor_loop():
            while not self._stop_monitoring.is_set():
                self.check_all()
                
                # Wait for shortest interval
                min_interval = min(
                    (s.interval for s in self.services.values() if s.enabled),
                    default=60
                )
                self._stop_monitoring.wait(min_interval)
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        print("[ServiceMonitor] Started continuous monitoring")
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring."""
        self._stop_monitoring.set()
        print("[ServiceMonitor] Stopped continuous monitoring")
    
    def get_dashboard_data(self) -> Dict:
        """Get data for dashboard display."""
        services_data = []
        
        for name, health in self.health_data.items():
            service = self.services.get(name)
            services_data.append({
                'name': name,
                'type': service.check_type if service else 'unknown',
                'target': service.target if service else '',
                'status': health.current_status,
                'uptime': health.uptime_percent,
                'avg_response_time': health.avg_response_time_ms,
                'last_check': health.last_check,
                'last_failure': health.last_failure
            })
        
        # Calculate overall status
        statuses = [h.current_status for h in self.health_data.values()]
        overall = ServiceStatus.HEALTHY.value
        if ServiceStatus.UNHEALTHY.value in statuses:
            overall = ServiceStatus.UNHEALTHY.value
        elif ServiceStatus.DEGRADED.value in statuses:
            overall = ServiceStatus.DEGRADED.value
        
        return {
            'overall_status': overall,
            'total_services': len(self.services),
            'healthy_count': statuses.count(ServiceStatus.HEALTHY.value),
            'degraded_count': statuses.count(ServiceStatus.DEGRADED.value),
            'unhealthy_count': statuses.count(ServiceStatus.UNHEALTHY.value),
            'services': services_data,
            'last_updated': datetime.now().isoformat()
        }
    
    def export(self, output_path: str):
        """Export monitoring data to JSON."""
        output = {
            'exported_at': datetime.now().isoformat(),
            'dashboard': self.get_dashboard_data(),
            'services': [s.to_dict() for s in self.services.values()],
            'health_data': [h.to_dict() for h in self.health_data.values()],
            'recent_results': [r.to_dict() for r in self.results_history[-50:]]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[+] Monitoring data exported to: {output_path}")


def main():
    """Demo usage of ServiceMonitor."""
    print("\n[IdentityOps] Service Monitor")
    print("=" * 50)
    
    monitor = ServiceMonitor()
    
    # Add sample services
    monitor.add_service(ServiceCheck(
        name="google",
        check_type="https",
        target="https://www.google.com",
        timeout=10
    ))
    
    monitor.add_service(ServiceCheck(
        name="localhost_web",
        check_type="tcp",
        target="localhost:80",
        timeout=5
    ))
    
    # Check all services
    results = monitor.check_all()
    
    # Display dashboard
    print(f"\nDashboard: {json.dumps(monitor.get_dashboard_data(), indent=2)}")
    
    # Export results
    monitor.export("./service-monitor-results.json")


if __name__ == "__main__":
    main()
