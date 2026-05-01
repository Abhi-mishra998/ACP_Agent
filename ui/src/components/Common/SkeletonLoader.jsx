import React from 'react'

/**
 * SkeletonLoader — shimmer placeholder while content loads.
 * Variants: 'card' | 'row' | 'text' | default (block)
 */
export default function SkeletonLoader({
  variant = 'card',
  className = '',
  count = 1,
}) {
  const pulse = 'animate-pulse'

  const renderSkeleton = (key) => {
    if (variant === 'card') {
      return (
        <div
          key={key}
          className={`p-5 bg-white/[0.02] border border-white/[0.04] rounded-xl space-y-4 ${pulse} ${className}`}
          aria-hidden="true"
        >
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-white/[0.05] rounded-lg shrink-0" />
            <div className="space-y-2 flex-1">
              <div className="h-2.5 bg-white/[0.06] rounded w-1/3" />
              <div className="h-2 bg-white/[0.04] rounded w-1/2" />
            </div>
          </div>
          <div className="space-y-2">
            <div className="h-2 bg-white/[0.04] rounded w-full" />
            <div className="h-2 bg-white/[0.04] rounded w-3/4" />
            <div className="h-2 bg-white/[0.03] rounded w-1/2" />
          </div>
        </div>
      )
    }

    if (variant === 'row') {
      return (
        <div
          key={key}
          className={`flex items-center gap-4 px-5 py-3.5 border-b border-white/[0.03] ${pulse} ${className}`}
          aria-hidden="true"
        >
          <div className="w-7 h-7 bg-white/[0.05] rounded-lg shrink-0" />
          <div className="h-2.5 bg-white/[0.07] rounded flex-1 max-w-[200px]" />
          <div className="h-2 bg-white/[0.04] rounded w-24" />
          <div className="h-2 bg-white/[0.04] rounded w-16" />
          <div className="h-5 bg-white/[0.04] rounded-full w-14 ml-auto" />
        </div>
      )
    }

    if (variant === 'text') {
      return (
        <div key={key} className={`space-y-2 ${pulse} ${className}`} aria-hidden="true">
          <div className="h-3 bg-white/[0.06] rounded w-3/4" />
          <div className="h-3 bg-white/[0.04] rounded w-full" />
          <div className="h-3 bg-white/[0.04] rounded w-5/6" />
        </div>
      )
    }

    /* Default: plain block */
    return (
      <div
        key={key}
        className={`bg-white/[0.03] border border-white/[0.04] rounded-xl ${pulse} ${className}`}
        style={{ minHeight: '6rem' }}
        aria-hidden="true"
      />
    )
  }

  return (
    <div
      className={variant === 'row' ? '' : 'space-y-4'}
      role="status"
      aria-label="Loading…"
    >
      {Array.from({ length: count }, (_, i) => renderSkeleton(i))}
      <span className="sr-only">Loading…</span>
    </div>
  )
}
