import React, { useState, useEffect, useCallback } from 'react'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
import CommandPalette from '../Common/CommandPalette'

export default function MainLayout({ children }) {
  const [sidebarOpen,  setSidebarOpen]  = useState(false)
  const [paletteOpen,  setPaletteOpen]  = useState(false)

  const openPalette  = useCallback(() => setPaletteOpen(true),  [])
  const closePalette = useCallback(() => setPaletteOpen(false), [])

  // Cmd+K / Ctrl+K global shortcut
  useEffect(() => {
    const handle = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => !v)
      }
    }
    document.addEventListener('keydown', handle)
    return () => document.removeEventListener('keydown', handle)
  }, [])

  return (
    <div className="h-screen bg-[var(--bg-base)] flex overflow-hidden">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <Topbar
          onMenuClick={() => setSidebarOpen((v) => !v)}
          onCommandPalette={openPalette}
        />

        <main
          id="main-content"
          className="flex-1 overflow-y-auto overflow-x-hidden bg-[var(--bg-base)] relative"
        >
          <div
            className="pointer-events-none fixed inset-0 grid-baseline opacity-[0.12]"
            aria-hidden="true"
          />
          <div className="relative z-10 w-full max-w-[1600px] mx-auto p-6 lg:p-8 animate-fade-in">
            {children}
          </div>
        </main>
      </div>

      <CommandPalette isOpen={paletteOpen} onClose={closePalette} />
    </div>
  )
}
