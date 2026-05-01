import React, { createContext, useState, useEffect, useCallback, useRef } from 'react'
import { registryService } from '../services/api'
import { useAuth } from '../hooks/useAuth'
import { useSSE } from '../hooks/useSSE'
import { eventBus } from '../lib/eventBus'

export const AgentContext = createContext({
  agents: [],
  selectedAgentId: null,
  selectedAgent: null,
  agentsLoading: false,
  sseConnected: false,
  fetchAgents: async () => {},
  setSelectedAgentId: () => {},
  refreshAgents: async () => {},
})

export function AgentProvider({ children }) {
  const { isAuthenticated, tenant_id } = useAuth()
  const [agents, setAgents]               = useState([])
  const [selectedAgentId, setSelectedAgentId] = useState(null)
  const [agentsLoading, setAgentsLoading] = useState(false)
  const [sseConnected, setSseConnected]   = useState(false)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  const fetchAgents = useCallback(async () => {
    if (!isAuthenticated) return
    setAgentsLoading(true)
    try {
      const res  = await registryService.listAgents()
      const list = Array.isArray(res)
        ? res
        : Array.isArray(res?.data)
        ? res.data
        : Array.isArray(res?.data?.data)
        ? res.data.data
        : []

      if (!mountedRef.current) return
      setAgents(list)

      setSelectedAgentId((prev) => {
        if (prev && list.find((a) => a.id === prev)) return prev
        const active = list.find((a) => (a.status || '').toLowerCase() === 'active')
        return active?.id || list[0]?.id || null
      })
    } catch (err) {
      console.error('AGENT_FETCH_FAILED:', err.message)
    } finally {
      if (mountedRef.current) setAgentsLoading(false)
    }
  }, [isAuthenticated])

  const fetchAgentsRef = useRef(fetchAgents)
  useEffect(() => { fetchAgentsRef.current = fetchAgents }, [fetchAgents])

  useEffect(() => {
    if (isAuthenticated) fetchAgents()
    else { setAgents([]); setSelectedAgentId(null) }
  }, [isAuthenticated, fetchAgents])

  const handleSSEMessage = useCallback((msg) => {
    switch (msg.type) {
      case 'agent_created':
      case 'agent_deleted':
      case 'agent_updated':
        fetchAgentsRef.current()
        eventBus.emit('agent_changed', msg.data)
        break
      case 'risk_updated':
        eventBus.emit('risk_updated', msg.data)
        break
      case 'billing_updated':
        eventBus.emit('billing_updated', msg.data)
        break
      case 'tool_executed':
        eventBus.emit('tool_executed', msg.data)
        break
      case 'insight_generated':
        eventBus.emit('insight_generated', msg.data)
        break
      case 'policy_decision':
        eventBus.emit('policy_decision', msg.data)
        break
      case 'alert':
        eventBus.emit('alert', msg.data)
        break
      default:
        break
    }
  }, [])

  useSSE({
    enabled: isAuthenticated && !!tenant_id,
    onMessage:   handleSSEMessage,
    onConnected: () => setSseConnected(true),
    onError:     () => setSseConnected(false),
  })

  const selectedAgent = agents.find((a) => a.id === selectedAgentId) ?? null

  return (
    <AgentContext.Provider
      value={{
        agents,
        selectedAgentId,
        selectedAgent,
        agentsLoading,
        sseConnected,
        fetchAgents,
        setSelectedAgentId,
        refreshAgents: fetchAgents,
      }}
    >
      {children}
    </AgentContext.Provider>
  )
}
