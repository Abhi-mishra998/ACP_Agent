import React from 'react'
import { Loader2, Database } from 'lucide-react'

/**
 * DataTable — responsive table with design system alignment.
 * Handles loading, empty, and data states.
 */
export default function DataTable({
  columns = [],
  data = [],
  isLoading = false,
  onRowClick = null,
  emptyMessage = 'No records found.',
  className = '',
}) {
  if (isLoading) {
    return (
      <div className="table-container flex flex-col items-center justify-center py-16 gap-3">
        <Loader2 className="w-5 h-5 text-neutral-600 animate-spin" />
        <p className="text-xs text-neutral-600">Loading…</p>
      </div>
    )
  }

  return (
    <div className={`table-container ${className}`}>
      <div className="table-scroll">
        <table className="table-base">
          <thead>
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className="table-th"
                  style={col.width ? { width: col.width, minWidth: col.width } : undefined}
                >
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-6 py-14 text-center">
                  <div className="flex flex-col items-center gap-3 opacity-40">
                    <Database size={32} className="text-neutral-700" />
                    <p className="text-xs font-medium text-neutral-500">{emptyMessage}</p>
                  </div>
                </td>
              </tr>
            ) : (
              data.map((row, idx) => (
                <tr
                  key={row.id || idx}
                  onClick={() => onRowClick?.(row)}
                  tabIndex={onRowClick ? 0 : undefined}
                  onKeyDown={onRowClick ? (e) => e.key === 'Enter' && onRowClick(row) : undefined}
                  className={`table-row ${onRowClick ? 'cursor-pointer focus-visible:bg-white/[0.03] outline-none' : ''}`}
                >
                  {columns.map((col) => (
                    <td key={col.key} className="table-td">
                      {col.render ? col.render(row[col.key], row) : (row[col.key] ?? '—')}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
