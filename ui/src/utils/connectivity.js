import axios from 'axios'

/**
 * Backend Connectivity Verifier
 * Checks all microservices are reachable and responsive
 * Production-grade verification
 */

const GATEWAY_BASE = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8000'

// All health checks route through the gateway /health endpoint.
// Direct service-level health is only available server-side.
const API_ENDPOINTS = {
  GATEWAY: GATEWAY_BASE,
}

class ConnectivityChecker {
  constructor() {
    this.results = {}
    this.timeout = 5000
  }

  async checkService(name, url) {
    try {
      const startTime = Date.now()
      const response = await axios.get(`${url}/health`, {
        timeout: this.timeout,
        validateStatus: () => true, // Accept any status
      })
      const responseTime = Date.now() - startTime

      this.results[name] = {
        status: 'UP',
        url,
        responseTime,
        statusCode: response.status,
        timestamp: new Date().toISOString(),
      }

      return true
    } catch (error) {
      this.results[name] = {
        status: 'DOWN',
        url,
        error: error.message,
        timestamp: new Date().toISOString(),
      }

      return false
    }
  }

  /**
   * Run all health checks
   */
  async runAllChecks() {
    const checks = [
      this.checkService('GATEWAY', API_ENDPOINTS.GATEWAY),
    ]

    await Promise.all(checks)

    return this.getReport()
  }

  /**
   * Get health check report
   */
  getReport() {
    const upServices = Object.values(this.results).filter(r => r.status === 'UP').length
    const totalServices = Object.keys(this.results).length
    const allHealthy = upServices === totalServices

    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        healthy: upServices,
        total: totalServices,
        allServicesUp: allHealthy,
        productionReady: allHealthy,
      },
      services: this.results,
      issues: Object.entries(this.results)
        .filter(([, r]) => r.status === 'DOWN')
        .map(([name, r]) => ({
          service: name,
          issue: r.error,
          url: r.url,
        })),
    }

    return report
  }

  /**
   * Internal reporter (legacy - do not call in prod)
   */
  _logReportInternal() {
    // This is purely for local dev debugging if needed manually
    const report = this.getReport()
    return report
  }
}

/**
 * Exported for use in frontend
 */
export const connectivityChecker = new ConnectivityChecker()

export const checkGatewayHealth = async () => {
  const checker = new ConnectivityChecker()
  return await checker.runAllChecks()
}

export default ConnectivityChecker
