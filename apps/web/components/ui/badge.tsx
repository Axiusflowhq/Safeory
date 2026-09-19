import { mergeProps } from "@base-ui/react/merge-props"
import { useRender } from "@base-ui/react/use-render"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "group/badge inline-flex h-5 w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-[var(--radius-large)] border border-transparent px-2 py-0.5 text-xs font-medium whitespace-nowrap focus-visible:border-[var(--ring)] focus-visible:ring-[3px] focus-visible:ring-[var(--ring)] has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 aria-invalid:border-[var(--danger)] aria-invalid:ring-[var(--danger)] motion-safe:transition-[background-color,color,border-color,box-shadow,opacity] motion-safe:duration-150 motion-safe:ease-out [&>svg]:pointer-events-none [&>svg]:size-3! [&>svg]:text-current",
  {
    variants: {
      variant: {
        default:
          "bg-[var(--primary)] text-[var(--primary-foreground)] [@media(hover:hover)]:[a]:hover:opacity-90",
        secondary:
          "bg-[var(--surface-secondary)] text-[var(--text-primary)] [@media(hover:hover)]:[a]:hover:bg-[var(--hover-bg)]",
        destructive:
          "bg-[var(--danger)] text-[var(--danger-foreground)] focus-visible:ring-[var(--danger)] [@media(hover:hover)]:[a]:hover:opacity-90",
        outline:
          "border-[var(--border)] text-[var(--text-primary)] [@media(hover:hover)]:[a]:hover:bg-[var(--hover-bg)]",
        ghost:
          "text-[var(--text-secondary)] [@media(hover:hover)]:hover:bg-[var(--hover-bg)]",
        link: "text-[var(--primary)] underline-offset-4 [@media(hover:hover)]:hover:underline",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({
  className,
  variant = "default",
  render,
  ...props
}: useRender.ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return useRender({
    defaultTagName: "span",
    props: mergeProps<"span">(
      {
        className: cn(badgeVariants({ variant }), className),
      },
      props
    ),
    render,
    state: {
      slot: "badge",
      variant,
    },
  })
}

export { Badge, badgeVariants }
