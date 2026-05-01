import { useAuth } from './useAuth'

export function useRole() {
  const { role } = useAuth()
  const normalized = (role || '').toUpperCase()
  return {
    role: normalized,
    isAdmin: normalized === 'ADMIN',
    isAuditor: normalized === 'AUDITOR',
    isViewer: normalized === 'VIEWER' || normalized === '',
    canMutate: normalized === 'ADMIN',
    canViewKillSwitch: normalized === 'ADMIN',
  }
}
