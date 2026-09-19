import type { ReactNode } from "react"

import { FancyButton } from "@/components/ui/fancy-button"

const variants = ["neutral", "primary", "destructive", "basic"] as const
const sizes = ["medium", "small", "xsmall"] as const

function SparkIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.75 13.9 8.1 19.25 10 13.9 11.9 12 17.25 10.1 11.9 4.75 10l5.35-1.9L12 2.75Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function ArrowIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M5 12h14m-5-5 5 5-5 5"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function ShowcaseSection({
  title,
  children,
}: {
  title: string
  children: ReactNode
}) {
  return (
    <section className="space-y-3">
      <h3 className="text-sm font-medium text-[var(--text-primary)]">
        {title}
      </h3>
      <div className="flex flex-wrap items-center gap-3">{children}</div>
    </section>
  )
}

function FancyButtonShowcase() {
  return (
    <div className="space-y-8 rounded-[var(--radius-default)] bg-[var(--surface)] p-6 text-[var(--text-primary)]">
      <div>
        <h2 className="text-lg font-semibold">FancyButton</h2>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Variants, sizes, icon layouts, loading behavior, and disabled states.
        </p>
      </div>

      {variants.map((variant) => (
        <ShowcaseSection key={variant} title={`${variant} sizes`}>
          {sizes.map((size) => (
            <FancyButton key={size} variant={variant} size={size}>
              {size}
            </FancyButton>
          ))}
        </ShowcaseSection>
      ))}

      <ShowcaseSection title="Icon layouts">
        <FancyButton leadingIcon={<SparkIcon />}>Leading icon</FancyButton>
        <FancyButton trailingIcon={<ArrowIcon />}>Trailing icon</FancyButton>
        <FancyButton leadingIcon={<SparkIcon />} trailingIcon={<ArrowIcon />}>
          Both icons
        </FancyButton>
      </ShowcaseSection>

      <ShowcaseSection title="Icon-only variants and sizes">
        {variants.flatMap((variant) =>
          sizes.map((size) => (
            <FancyButton
              key={`${variant}-${size}`}
              variant={variant}
              size={size}
              leadingIcon={<SparkIcon />}
              aria-label={`${variant} ${size} icon button`}
            />
          ))
        )}
      </ShowcaseSection>

      <ShowcaseSection title="Loading states">
        {variants.map((variant) => (
          <FancyButton key={variant} variant={variant} loading>
            Loading
          </FancyButton>
        ))}
        <FancyButton
          loading
          leadingIcon={<SparkIcon />}
          aria-label="Loading icon action"
        />
      </ShowcaseSection>

      <ShowcaseSection title="Disabled states">
        {variants.map((variant) => (
          <FancyButton key={variant} variant={variant} disabled>
            Disabled
          </FancyButton>
        ))}
      </ShowcaseSection>
    </div>
  )
}

export { FancyButtonShowcase }
