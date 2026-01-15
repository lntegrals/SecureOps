"""
Integration Dashboard Flask Backend - REST API for service health monitoring.

This Flask application provides endpoints for:
- Service health status
- Uptime metrics
- Log retrieval status
- Integration health dashboard data

Author: IdentityOps Automation Suite
Version: 1.0.0
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import platform
import threading
import time
from typing import Dict, List

app = Flask(__name__)
CORS(app)


# Demo data for services
services_data = {
    'services': [
        {'name': 'Active Directory', 'type': 'ldap', 'status': 'healthy', 'uptime': 99.95, 'response_time': 45},
        {'name': 'Email Server', 'type': 'smtp', 'status': 'healthy', 'uptime': 99.87, 'response_time': 120},
        {'name': 'File Server', 'type': 'smb', 'status': 'healthy', 'uptime': 99.99, 'response_time': 25},
        {'name': 'Database', 'type': 'sql', 'status': 'healthy', 'uptime': 99.92, 'response_time': 35},
        {'name': 'Web Portal', 'type': 'https', 'status': 'warning', 'uptime': 98.5, 'response_time': 850},
    ],
    'last_updated': datetime.now().isoformat()
}

# Demo uptime history
uptime_history = []
for i in range(24):
    hour = datetime.now() - timedelta(hours=i)
    uptime_history.append({
        'timestamp': hour.isoformat(),
        'overall_uptime': 99.5 + (i % 5) * 0.1,
        'services_up': 5 - (1 if i % 8 == 0 else 0),
        'services_total': 5
    })

# Demo incidents
incidents = [
    {'id': 'INC-001', 'service': 'Web Portal', 'severity': 'warning', 'start_time': (datetime.now() - timedelta(hours=2)).isoformat(), 'status': 'active', 'message': 'High response time detected'},
    {'id': 'INC-002', 'service': 'Email Server', 'severity': 'info', 'start_time': (datetime.now() - timedelta(days=1)).isoformat(), 'status': 'resolved', 'message': 'Scheduled maintenance completed'},
]

# Demo log sources
log_sources = [
    {'name': 'Security Events', 'type': 'windows_event', 'status': 'active', 'last_retrieved': datetime.now().isoformat(), 'entries_count': 1250},
    {'name': 'Application Logs', 'type': 'file', 'status': 'active', 'last_retrieved': datetime.now().isoformat(), 'entries_count': 3420},
    {'name': 'System Logs', 'type': 'windows_event', 'status': 'active', 'last_retrieved': datetime.now().isoformat(), 'entries_count': 890},
]


@app.route('/api/health', methods=['GET'])
def get_health():
    """API health check endpoint."""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })


@app.route('/api/services', methods=['GET'])
def get_services():
    """Get all monitored services."""
    return jsonify({
        'services': services_data['services'],
        'total': len(services_data['services']),
        'healthy': len([s for s in services_data['services'] if s['status'] == 'healthy']),
        'warning': len([s for s in services_data['services'] if s['status'] == 'warning']),
        'critical': len([s for s in services_data['services'] if s['status'] == 'critical']),
        'last_updated': services_data['last_updated']
    })


@app.route('/api/services/<name>', methods=['GET'])
def get_service(name):
    """Get details for a specific service."""
    service = next((s for s in services_data['services'] if s['name'].lower() == name.lower()), None)
    
    if not service:
        return jsonify({'error': 'Service not found'}), 404
    
    return jsonify(service)


@app.route('/api/uptime', methods=['GET'])
def get_uptime():
    """Get uptime statistics."""
    period = request.args.get('period', '24h')
    
    hours = {'24h': 24, '7d': 168, '30d': 720}.get(period, 24)
    
    # Calculate averages
    avg_uptime = sum(h['overall_uptime'] for h in uptime_history) / len(uptime_history) if uptime_history else 100
    
    return jsonify({
        'period': period,
        'average_uptime': round(avg_uptime, 2),
        'sla_target': 99.9,
        'sla_compliant': avg_uptime >= 99.9,
        'history': uptime_history[:hours],
        'last_updated': datetime.now().isoformat()
    })


@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    """Get all incidents."""
    status = request.args.get('status')
    
    filtered = incidents
    if status:
        filtered = [i for i in incidents if i['status'] == status]
    
    return jsonify({
        'incidents': filtered,
        'total': len(filtered),
        'active': len([i for i in filtered if i['status'] == 'active']),
        'resolved': len([i for i in filtered if i['status'] == 'resolved'])
    })


@app.route('/api/logs/sources', methods=['GET'])
def get_log_sources():
    """Get log source status."""
    return jsonify({
        'sources': log_sources,
        'total': len(log_sources),
        'active': len([s for s in log_sources if s['status'] == 'active'])
    })


@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    """Get all dashboard data."""
    services = services_data['services']
    
    # Calculate overall status
    statuses = [s['status'] for s in services]
    overall = 'healthy'
    if 'critical' in statuses:
        overall = 'critical'
    elif 'warning' in statuses:
        overall = 'warning'
    
    # Calculate average uptime
    avg_uptime = sum(s['uptime'] for s in services) / len(services) if services else 100
    
    return jsonify({
        'overall_status': overall,
        'services': {
            'total': len(services),
            'healthy': len([s for s in services if s['status'] == 'healthy']),
            'warning': len([s for s in services if s['status'] == 'warning']),
            'critical': len([s for s in services if s['status'] == 'critical']),
            'list': services
        },
        'uptime': {
            'average': round(avg_uptime, 2),
            'sla_target': 99.9,
            'sla_compliant': avg_uptime >= 99.9
        },
        'incidents': {
            'active': len([i for i in incidents if i['status'] == 'active']),
            'recent': [i for i in incidents if i['status'] == 'active'][:5]
        },
        'logs': {
            'sources': len(log_sources),
            'active': len([s for s in log_sources if s['status'] == 'active']),
            'total_entries': sum(s['entries_count'] for s in log_sources)
        },
        'system': {
            'hostname': platform.node(),
            'platform': platform.system()
        },
        'last_updated': datetime.now().isoformat()
    })


@app.route('/api/provisioning/stats', methods=['GET'])
def get_provisioning_stats():
    """Get user provisioning statistics."""
    return jsonify({
        'today': {
            'users_created': 5,
            'users_modified': 12,
            'users_disabled': 1,
            'groups_updated': 8
        },
        'week': {
            'users_created': 23,
            'users_modified': 67,
            'users_disabled': 4,
            'groups_updated': 45
        },
        'pending_reviews': 3,
        'last_updated': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("\n[IdentityOps] Integration Dashboard API")
    print("=" * 50)
    print("Starting server...")
    
    app.run(host='0.0.0.0', port=5001, debug=False)
