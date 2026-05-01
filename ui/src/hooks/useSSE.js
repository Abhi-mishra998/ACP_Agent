import { useEffect, useRef, useCallback } from 'react'

const API_BASE = import.meta.env.VITE_GATEWAY_URL || ''
const MAX_BACKOFF_MS = 32_000

export function useSSE({ enabled = true, onMessage, onConnected, onError } = {}) {
  const esRef              = useRef(null)
  const reconnectTimerRef  = useRef(null)
  const attemptsRef        = useRef(0)
  const mountedRef         = useRef(true)
  const onMessageRef       = useRef(onMessage)
  const onConnectedRef     = useRef(onConnected)
  const onErrorRef         = useRef(onError)

  useEffect(() => { onMessageRef.current   = onMessage   }, [onMessage])
  useEffect(() => { onConnectedRef.current = onConnected }, [onConnected])
  useEffect(() => { onErrorRef.current     = onError     }, [onError])

  const connect = useCallback(() => {
    if (!mountedRef.current || !enabled) return

    const backoffMs = Math.min(1_000 * 2 ** attemptsRef.current, MAX_BACKOFF_MS)
    const es = new EventSource(`${API_BASE}/events/stream`, { withCredentials: true })
    esRef.current = es

    es.addEventListener('connected', (e) => {
      attemptsRef.current = 0
      onConnectedRef.current?.(e.data)
    })

    es.addEventListener('heartbeat', () => {})

    es.onmessage = (event) => {
      try {
        onMessageRef.current?.(JSON.parse(event.data))
      } catch {
        // malformed SSE frame — ignore
      }
    }

    es.onerror = () => {
      es.close()
      esRef.current = null
      attemptsRef.current += 1
      onErrorRef.current?.()
      if (mountedRef.current) {
        reconnectTimerRef.current = setTimeout(connect, backoffMs)
      }
    }
  }, [enabled]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    mountedRef.current = true
    if (enabled) connect()
    return () => {
      mountedRef.current = false
      clearTimeout(reconnectTimerRef.current)
      esRef.current?.close()
      esRef.current = null
    }
  }, [enabled, connect])

  const reconnect = useCallback(() => {
    clearTimeout(reconnectTimerRef.current)
    esRef.current?.close()
    esRef.current = null
    attemptsRef.current = 0
    connect()
  }, [connect])

  return { reconnect }
}
