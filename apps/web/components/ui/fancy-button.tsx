import * as React from "react"
import { Button as ButtonPrimitive } from "@base-ui/react/button"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const fancyButtonBase =
  "group relative inline-flex shrink-0 cursor-pointer items-center justify-center whitespace-nowrap text-sm font-medium tracking-[-0.006em] outline-none motion-safe:transition-[scale] motion-safe:duration-200 motion-safe:ease-out motion-safe:will-change-transform focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)] active:scale-[0.97] disabled:pointer-events-none disabled:scale-100 disabled:bg-[var(--surface-secondary)] disabled:bg-none disabled:text-[var(--text-muted)] disabled:shadow-none disabled:before:hidden disabled:after:hidden [&_svg]:shrink-0 [&_svg]:text-current [&_svg:not([class*='size-'])]:size-5"

const glossOverlay =
  "before:pointer-events-none before:absolute before:inset-0 before:z-10 before:rounded-[inherit] before:bg-gradient-to-b before:p-px before:from-white/[.12] before:to-transparent before:[mask-clip:content-box,border-box] before:[mask-composite:exclude] before:[mask-image:linear-gradient(#fff_0_0),linear-gradient(#fff_0_0)] after:pointer-events-none after:absolute after:inset-0 after:rounded-[inherit] after:bg-gradient-to-b after:from-white after:to-transparent after:opacity-[.16] motion-safe:after:transition-opacity motion-safe:after:duration-200 motion-safe:after:ease-out [@media(hover:hover)]:hover:after:opacity-[.24]"

const fancyButtonVariants = cva(fancyButtonBase, {
  variants: {
    variant: {
      neutral:
        "bg-[var(--button-fill)] text-[var(--surface)] shadow-[var(--fancy-shadow-neutral)]",
      primary:
        "bg-[var(--primary)] text-[var(--primary-foreground)] shadow-[var(--fancy-shadow-primary)]",
      destructive:
        "bg-[var(--danger)] text-[var(--danger-foreground)] shadow-[var(--fancy-shadow-destructive)]",
      basic:
        "bg-[var(--surface)] text-[var(--text-secondary)] shadow-[var(--fancy-shadow-basic)] [@media(hover:hover)]:hover:bg-[var(--surface-secondary)] [@media(hover:hover)]:hover:text-[var(--text-primary)] [@media(hover:hover)]:hover:shadow-none",
    },
    size: {
      medium: "h-10 gap-3 rounded-[var(--radius-default)] px-3.5",
      small: "h-9 gap-3 rounded-[var(--radius-default)] px-3",
      xsmall: "h-8 gap-3 rounded-[var(--radius-default)] px-2.5",
    },
  },
  compoundVariants: [
    {
      variant: ["neutral", "primary", "destructive"],
      className: glossOverlay,
    },
  ],
  defaultVariants: {
    variant: "neutral",
    size: "medium",
  },
})

const iconOnlySizes = {
  medium: "w-10 gap-0 px-0",
  small: "w-9 gap-0 px-0",
  xsmall: "w-8 gap-0 px-0",
} as const

const iconClassName =
  "relative z-10 -mx-1 inline-flex size-5 shrink-0 items-center justify-center [&_svg]:size-full"

type FancyButtonVariant = NonNullable<
  VariantProps<typeof fancyButtonVariants>["variant"]
>
type FancyButtonSize = NonNullable<
  VariantProps<typeof fancyButtonVariants>["size"]
>

type FancyButtonProps = Omit<ButtonPrimitive.Props, "className" | "ref"> & {
  className?: string
  variant?: FancyButtonVariant
  size?: FancyButtonSize
  leadingIcon?: React.ReactNode
  trailingIcon?: React.ReactNode
  loading?: boolean
}

const FancyButton = React.forwardRef<HTMLButtonElement, FancyButtonProps>(
  (
    {
      className,
      variant = "neutral",
      size = "medium",
      leadingIcon,
      trailingIcon,
      loading = false,
      disabled,
      type = "button",
      children,
      ...props
    },
    ref
  ) => {
    const hasChildren = React.Children.count(children) > 0
    const hasSingleIcon = Boolean(leadingIcon) !== Boolean(trailingIcon)
    const iconOnly = !hasChildren && hasSingleIcon
    const resolvedSize = size ?? "medium"

    return (
      <ButtonPrimitive
        {...props}
        ref={ref as React.Ref<HTMLElement>}
        type={type}
        disabled={disabled || loading}
        aria-busy={loading || undefined}
        data-slot="fancy-button"
        className={cn(
          fancyButtonVariants({ variant, size: resolvedSize }),
          iconOnly && iconOnlySizes[resolvedSize],
          className
        )}
      >
        {loading ? (
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            className="relative z-10 size-5 motion-safe:animate-spin"
          >
            <circle
              cx="12"
              cy="12"
              r="9"
              stroke="currentColor"
              strokeWidth="2.5"
              className="opacity-25"
            />
            <path
              d="M21 12a9 9 0 0 0-9-9"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
            />
          </svg>
        ) : leadingIcon ? (
          <span aria-hidden="true" className={iconClassName}>
            {leadingIcon}
          </span>
        ) : null}

        {!iconOnly && hasChildren ? (
          <span className="relative z-10">{children}</span>
        ) : null}

        {!loading && trailingIcon ? (
          <span aria-hidden="true" className={iconClassName}>
            {trailingIcon}
          </span>
        ) : null}
      </ButtonPrimitive>
    )
  }
)

FancyButton.displayName = "FancyButton"

export { FancyButton, fancyButtonVariants }
export type { FancyButtonProps }
