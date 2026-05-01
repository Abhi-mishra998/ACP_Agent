import React from 'react'
import { TrendingUp, TrendingDown } from 'lucide-react'

/**
 * Card — dual-mode:
 *   - KPI mode (value + title + subtitle + trend) when `value` is provided
 *   - Container mode (title + children) otherwise
 */
export default function Card({
  children,
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  trendValue,
  className = '',
  onClick = null,
}) {
  const isPositive = trend === 'up'

  return (
    <div
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick(e) : undefined}
      className={`card-premium p-5 flex flex-col gap-4 ${onClick ? 'cursor-pointer' : ''} ${className}`}
    >
      {value !== undefined ? (
        /* ── KPI mode ── */
        <div className="space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-1 min-w-0">
              <p className="text-label truncate">{title}</p>
              <p className="text-2xl font-bold tracking-tight text-white leading-none mt-1.5">
                {value}
              </p>
              {subtitle && (
                <p className="text-xs text-neutral-500 font-medium mt-1">{subtitle}</p>
              )}
            </div>
            {Icon && (
              <div className="p-2.5 rounded-lg bg-white/[0.04] border border-white/[0.06] text-neutral-500 shrink-0 mt-0.5">
                <Icon size={18} />
              </div>
            )}
          </div>

          {trendValue && (
            <div className="flex items-center gap-2 pt-3 border-t border-[var(--border-subtle)]">
              <span
                className={`inline-flex items-center gap-1 text-xs font-semibold px-1.5 py-0.5 rounded ${
                  isPositive
                    ? 'text-green-400 bg-green-500/10'
                    : 'text-red-400 bg-red-500/10'
                }`}
              >
                {isPositive ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
                {trendValue}
              </span>
              <span className="text-xs text-neutral-600 font-medium">vs baseline</span>
            </div>
          )}
        </div>
      ) : (
        /* ── Container mode ── */
        <div className="flex flex-col h-full">
          {title && (
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-xs font-bold text-white tracking-wide uppercase">{title}</h3>
              {Icon && <Icon className="text-neutral-600 shrink-0" size={15} />}
            </div>
          )}
          <div className="flex-1">{children}</div>
        </div>
      )}
    </div>
  )
}

export function CardHeader({ title, subtitle, icon: Icon, action }) {
  return (
    <div className="flex items-start justify-between mb-6 gap-4">
      <div className="space-y-0.5 min-w-0">
        <h3 className="text-base font-bold text-white tracking-tight">{title}</h3>
        {subtitle && <p className="text-xs text-neutral-500">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {action}
        {Icon && <Icon className="text-neutral-700" size={20} />}
      </div>
    </div>
  )
}

export function CardBody({ children, className = '' }) {
  return <div className={`flex-1 ${className}`}>{children}</div>
}

export function CardFooter({ children, className = '' }) {
  return (
    <div className={`mt-5 pt-5 border-t border-[var(--border-subtle)] ${className}`}>
      {children}
    </div>
  )
}
