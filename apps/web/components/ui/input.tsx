import * as React from "react"
import { Input as InputPrimitive } from "@base-ui/react/input"
import { cn } from "cn"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <InputPrimitive
      type={type}
      data-slot="input"
      className={cn(
        "h-8 w-full min-w-0 rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-2.5 py-1 text-base text-[var(--text-primary)] transition-colors outline-none file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)] disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-[var(--danger)] aria-invalid:ring-3 aria-invalid:ring-[var(--danger)] md:text-sm",
        className
      )}
      {...props}
    />
  )
}

export { Input }
