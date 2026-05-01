import { useContext } from 'react'
import { AgentContext } from '../context/AgentContext'

export const useAgents = () => useContext(AgentContext)
