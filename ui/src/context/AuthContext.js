import { createContext } from 'react'

export const AuthContext = createContext({
  isAuthenticated: false,
  user: null,
  tenant_id: null,
  token: null,
  role: null,
  toasts: [],
  updateAuth: () => {},
  addToast: () => {},
  removeToast: () => {},
})
