import React from 'react'

/**
 * Button — production-grade with full variant, size, loading, and a11y support.
 * All icon-only buttons should pass `aria-label` via ...props.
 */
export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  className = '',
  type = 'button',
  ...props
}) {
  const base =
    'btn-premium inline-flex items-center justify-center font-semibold select-none transition-all focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white/60'

  const variants = {
    primary:
      'bg-white text-black border border-white/10 hover:bg-neutral-100 shadow-[0_0_16px_rgba(255,255,255,0.08)]',
    secondary:
      'bg-[var(--bg-surface-elevated)] text-white border border-[var(--border-default)] hover:border-white/25 hover:bg-white/[0.06]',
    danger:
      'bg-red-500/10 text-red-400 border border-red-500/25 hover:bg-red-500 hover:text-white hover:border-red-500',
    ghost:
      'bg-transparent text-neutral-400 hover:text-white hover:bg-white/[0.06] border border-transparent',
    outline:
      'border border-[var(--border-default)] text-neutral-300 hover:border-white/40 hover:text-white bg-transparent',
    success:
      'bg-green-500/10 text-green-400 border border-green-500/25 hover:bg-green-500 hover:text-white hover:border-green-500',
  }

  const sizes = {
    xs:  'px-2.5 py-1 text-xs gap-1.5 rounded-md',
    sm:  'px-3.5 py-1.5 text-xs gap-1.5 rounded-lg',
    md:  'px-5 py-2.5 text-sm gap-2 rounded-lg',
    lg:  'px-7 py-3.5 text-sm gap-2 rounded-xl',
    icon: 'p-2 rounded-lg',
  }

  return (
    <button
      type={type}
      disabled={disabled || loading}
      aria-disabled={disabled || loading}
      aria-busy={loading}
      className={`${base} ${variants[variant] ?? variants.primary} ${sizes[size] ?? sizes.md} ${className}`}
      {...props}
    >
      {loading ? (
        <>
          <span
            className="w-4 h-4 rounded-full border-2 border-current border-t-transparent animate-spin shrink-0"
            aria-hidden="true"
          />
          <span>Loading…</span>
        </>
      ) : (
        children
      )}
    </button>
  )
}
