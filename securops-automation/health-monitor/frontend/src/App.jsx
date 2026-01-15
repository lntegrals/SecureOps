import { useState, useEffect } from 'react'

const API_BASE = '/api'

// Mock data for when API is not available
const mockData = {
    health: {
        checks: {
            cpu: { name: 'CPU Usage', status: 'healthy', value: 45, threshold: 70, message: 'CPU usage at 45%', metadata: { cores: 8 } },
            memory: { name: 'Memory Usage', status: 'healthy', value: 62, threshold: 80, message: 'Memory usage at 62%', metadata: { total_gb: 16, available_gb: 6.1 } },
            disk: { name: 'Disk Usage', status: 'warning', value: 82, threshold: 80, message: 'Disk usage at 82%', metadata: { total_gb: 500, free_gb: 90 } },
            network: { name: 'Network I/O', status: 'healthy', value: null, message: 'Network operational', metadata: { bytes_sent_mb: 1024, bytes_recv_mb: 2048 } },
            processes: { name: 'Process Count', status: 'healthy', value: 245, threshold: 500, message: '245 processes running', metadata: {} }
        },
        summary: { healthy: 4, warning: 1, critical: 0 }
    },
    alerts: {
        active: 2,
        unacknowledged: 1,
        recent: [
            { id: 'a1', timestamp: new Date().toISOString(), severity: 'warning', source: 'Disk Usage', title: 'Disk Usage Alert', message: 'Disk usage at 82%', acknowledged: false },
            { id: 'a2', timestamp: new Date(Date.now() - 3600000).toISOString(), severity: 'info', source: 'System', title: 'System Update', message: 'System update available', acknowledged: true }
        ]
    },
    system: {
        hostname: 'SECUROPS-SERVER',
        uptime: '5 days, 12:34:56'
    },
    last_update: new Date().toISOString()
}

function App() {
    const [dashboardData, setDashboardData] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [useMock, setUseMock] = useState(false)

    const fetchDashboard = async () => {
        try {
            const response = await fetch(`${API_BASE}/dashboard`)
            if (!response.ok) throw new Error('API unavailable')
            const data = await response.json()
            setDashboardData(data)
            setUseMock(false)
            setError(null)
        } catch (err) {
            // Use mock data if API is not available
            setDashboardData(mockData)
            setUseMock(true)
            setError(null)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchDashboard()
        const interval = setInterval(fetchDashboard, 30000) // Refresh every 30s
        return () => clearInterval(interval)
    }, [])

    const getOverallStatus = () => {
        if (!dashboardData) return 'unknown'
        const { summary } = dashboardData.health
        if (summary.critical > 0) return 'critical'
        if (summary.warning > 0) return 'warning'
        return 'healthy'
    }

    const formatTime = (isoString) => {
        const date = new Date(isoString)
        return date.toLocaleTimeString()
    }

    const getStatusClass = (status) => {
        switch (status?.toLowerCase()) {
            case 'healthy': return 'healthy'
            case 'warning': return 'warning'
            case 'critical':
            case 'error': return 'critical'
            default: return ''
        }
    }

    const acknowledgeAlert = async (alertId) => {
        try {
            await fetch(`${API_BASE}/alerts/${alertId}/acknowledge`, { method: 'POST' })
            fetchDashboard()
        } catch (err) {
            console.error('Failed to acknowledge alert:', err)
        }
    }

    const resolveAlert = async (alertId) => {
        try {
            await fetch(`${API_BASE}/alerts/${alertId}/resolve`, { method: 'POST' })
            fetchDashboard()
        } catch (err) {
            console.error('Failed to resolve alert:', err)
        }
    }

    if (loading) {
        return (
            <div className="app">
                <div className="loading">
                    <div className="loading__spinner"></div>
                    <span>Loading health data...</span>
                </div>
            </div>
        )
    }

    const { health, alerts, system } = dashboardData

    return (
        <div className="app">
            {/* Header */}
            <header className="header">
                <div className="header__title">
                    <div className="header__logo">🛡️</div>
                    <div>
                        <h1>SecurOps Health Monitor</h1>
                        <span className="header__subtitle">Real-time System Monitoring Dashboard</span>
                    </div>
                </div>
                <div className="header__status">
                    <span className={`status-indicator status-indicator--${getOverallStatus()}`}></span>
                    <span>System Status: <strong style={{ textTransform: 'capitalize' }}>{getOverallStatus()}</strong></span>
                    {useMock && <span style={{ fontSize: '0.75rem', color: 'var(--color-warning)' }}>(Demo Mode)</span>}
                </div>
            </header>

            {/* Dashboard */}
            <div className="dashboard">
                {/* Summary Stats */}
                <div className="card card--full">
                    <div className="card__header">
                        <h2 className="card__title">Health Overview</h2>
                        <span className="card__badge card__badge--healthy">
                            Last updated: {formatTime(dashboardData.last_update || new Date().toISOString())}
                        </span>
                    </div>
                    <div className="summary-stats">
                        <div className="summary-stat">
                            <div className="summary-stat__value summary-stat__value--healthy">{health.summary.healthy}</div>
                            <div className="summary-stat__label">Healthy</div>
                        </div>
                        <div className="summary-stat">
                            <div className="summary-stat__value summary-stat__value--warning">{health.summary.warning}</div>
                            <div className="summary-stat__label">Warnings</div>
                        </div>
                        <div className="summary-stat">
                            <div className="summary-stat__value summary-stat__value--critical">{health.summary.critical}</div>
                            <div className="summary-stat__label">Critical</div>
                        </div>
                    </div>
                </div>

                {/* Metric Cards */}
                <div className="metric-grid">
                    {Object.entries(health.checks).map(([key, check]) => (
                        <div key={key} className={`metric-card metric-card--${getStatusClass(check.status)}`}>
                            <span className={`metric-card__status status-indicator status-indicator--${getStatusClass(check.status)}`}></span>
                            <div className="metric-card__icon">
                                {key === 'cpu' && '⚡'}
                                {key === 'memory' && '💾'}
                                {key === 'disk' && '💿'}
                                {key === 'network' && '🌐'}
                                {key === 'processes' && '⚙️'}
                            </div>
                            <div className="metric-card__value">
                                {check.value !== null ? `${check.value}%` : '—'}
                            </div>
                            <div className="metric-card__label">{check.name}</div>
                            {check.value !== null && (
                                <div className="progress-bar">
                                    <div
                                        className={`progress-bar__fill progress-bar__fill--${getStatusClass(check.status)}`}
                                        style={{ width: `${Math.min(check.value, 100)}%` }}
                                    ></div>
                                </div>
                            )}
                        </div>
                    ))}
                </div>

                {/* Alerts */}
                <div className="card card--half">
                    <div className="card__header">
                        <h2 className="card__title">Active Alerts</h2>
                        <span className={`card__badge ${alerts.unacknowledged > 0 ? 'card__badge--warning' : 'card__badge--healthy'}`}>
                            {alerts.active} Active
                        </span>
                    </div>
                    <div className="alerts-list">
                        {alerts.recent && alerts.recent.length > 0 ? (
                            alerts.recent.map(alert => (
                                <div key={alert.id} className={`alert-item alert-item--${alert.severity}`}>
                                    <span className="alert-item__icon">
                                        {alert.severity === 'critical' && '🔴'}
                                        {alert.severity === 'warning' && '🟡'}
                                        {alert.severity === 'error' && '🔴'}
                                        {alert.severity === 'info' && '🔵'}
                                    </span>
                                    <div className="alert-item__content">
                                        <div className="alert-item__title">{alert.title}</div>
                                        <div className="alert-item__message">{alert.message}</div>
                                        <div className="alert-item__time">{formatTime(alert.timestamp)}</div>
                                    </div>
                                    <div className="alert-item__actions">
                                        {!alert.acknowledged && (
                                            <button className="btn btn--secondary" onClick={() => acknowledgeAlert(alert.id)}>
                                                Ack
                                            </button>
                                        )}
                                        <button className="btn btn--primary" onClick={() => resolveAlert(alert.id)}>
                                            Resolve
                                        </button>
                                    </div>
                                </div>
                            ))
                        ) : (
                            <div className="empty-state">
                                <div className="empty-state__icon">✅</div>
                                <p>No active alerts</p>
                            </div>
                        )}
                    </div>
                </div>

                {/* System Info */}
                <div className="card card--half">
                    <div className="card__header">
                        <h2 className="card__title">System Information</h2>
                    </div>
                    <div className="system-info">
                        <div className="system-info__item">
                            <span className="system-info__label">Hostname</span>
                            <span className="system-info__value">{system.hostname}</span>
                        </div>
                        <div className="system-info__item">
                            <span className="system-info__label">Uptime</span>
                            <span className="system-info__value">{system.uptime}</span>
                        </div>
                        {health.checks.memory?.metadata && (
                            <>
                                <div className="system-info__item">
                                    <span className="system-info__label">Total Memory</span>
                                    <span className="system-info__value">{health.checks.memory.metadata.total_gb} GB</span>
                                </div>
                                <div className="system-info__item">
                                    <span className="system-info__label">Available Memory</span>
                                    <span className="system-info__value">{health.checks.memory.metadata.available_gb} GB</span>
                                </div>
                            </>
                        )}
                        {health.checks.disk?.metadata && (
                            <>
                                <div className="system-info__item">
                                    <span className="system-info__label">Total Disk</span>
                                    <span className="system-info__value">{health.checks.disk.metadata.total_gb} GB</span>
                                </div>
                                <div className="system-info__item">
                                    <span className="system-info__label">Free Disk</span>
                                    <span className="system-info__value">{health.checks.disk.metadata.free_gb} GB</span>
                                </div>
                            </>
                        )}
                        {health.checks.cpu?.metadata && (
                            <div className="system-info__item">
                                <span className="system-info__label">CPU Cores</span>
                                <span className="system-info__value">{health.checks.cpu.metadata.cores}</span>
                            </div>
                        )}
                        {health.checks.processes && (
                            <div className="system-info__item">
                                <span className="system-info__label">Running Processes</span>
                                <span className="system-info__value">{health.checks.processes.value}</span>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}

export default App
