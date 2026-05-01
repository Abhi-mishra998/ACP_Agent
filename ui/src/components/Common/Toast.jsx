import React, { useState, useEffect } from 'react'
import { AlertCircle, CheckCircle, Info, X } from 'lucide-react'

/**
 * Toast Component (Item)
 * Styled for "Next Level" UIUX with glassmorphism and smooth transitions.
 */
export default function Toast({ message, type, onClose }) {
  const [isClosing, setIsClosing] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => {
      handleClose()
    }, 5000)

    return () => clearTimeout(timer)
  }, [])

  const handleClose = () => {
    setIsClosing(true)
    setTimeout(onClose, 300)
  }

  const colors = {
    success: 'bg-emerald-900/90 text-emerald-100 border-emerald-500/50 shadow-emerald-500/20',
    error: 'bg-rose-900/90 text-rose-100 border-rose-500/50 shadow-rose-500/20',
    warning: 'bg-amber-900/90 text-amber-100 border-amber-500/50 shadow-amber-500/20',
    info: 'bg-blue-900/90 text-blue-100 border-blue-500/50 shadow-blue-500/20',
  }

  const icons = {
    success: <CheckCircle size={18} className="text-emerald-400" />,
    error: <AlertCircle size={18} className="text-rose-400" />,
    warning: <AlertCircle size={18} className="text-amber-400" />,
    info: <Info size={18} className="text-blue-400" />,
  }

  return (
    <div
      className={`
        flex items-center gap-3 px-4 py-3 rounded-xl border backdrop-blur-md shadow-xl 
        transform transition-all duration-300 ease-out
        ${colors[type] || colors.info}
        ${isClosing ? 'translate-x-full opacity-0' : 'translate-x-0 opacity-100'}
      `}
    >
      <div className="flex-shrink-0">
        {icons[type]}
      </div>
      <div className="flex-1 text-sm font-medium pr-2">
        {message}
      </div>
      <button
        onClick={handleClose}
        className="flex-shrink-0 text-white/50 hover:text-white transition-colors"
      >
        <X size={16} />
      </button>
    </div>
  )
}
