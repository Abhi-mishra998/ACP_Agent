import { useContext } from 'react'
import { AuthContext } from '../context/AuthContext'

/**
 * Global Toast Hook
 * Consumes the centralized toast system from AuthContext.
 */
export function useToast() {
  const context = useContext(AuthContext)
  
  if (!context) {
    // Fallback if used outside AuthContext, though App.jsx should always provide it
    return {
      toasts: [],
      addToast: (msg, type) => console.log(`Toast [${type}]: ${msg}`),
      removeToast: () => {}
    }
  }

  return {
    toasts: context.toasts || [],
    addToast: context.addToast,
    removeToast: context.removeToast
  }
}
