import * as React from "react"
import { cn } from "@/lib/utils"

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "flex field-sizing-content min-h-16 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-2.5 py-2 text-base text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)] focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)] disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-[var(--danger)] aria-invalid:ring-3 aria-invalid:ring-[var(--danger)] motion-safe:transition-[background-color,border-color,box-shadow,color] motion-safe:duration-150 motion-safe:ease-out md:text-sm",
        className
      )}
      {...props}
    />
  )
}

export { Textarea }
