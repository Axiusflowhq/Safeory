import { Button as ButtonPrimitive } from "@base-ui/react/button"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center rounded-[var(--radius-default)] border border-transparent bg-clip-padding text-sm font-medium whitespace-nowrap outline-none select-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)] active:scale-[0.97] disabled:pointer-events-none disabled:scale-100 disabled:opacity-50 aria-invalid:border-[var(--danger)] aria-invalid:ring-3 aria-invalid:ring-[var(--danger)] motion-safe:transition-[scale] motion-safe:duration-200 motion-safe:ease-out motion-safe:will-change-transform [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg]:text-current [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "bg-[var(--primary)] text-[var(--primary-foreground)] [&_svg]:text-[var(--primary-foreground)] [@media(hover:hover)]:hover:opacity-90",
        outline:
          "border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)] aria-expanded:bg-[var(--active-bg)] [&_svg]:text-[var(--icon)] [@media(hover:hover)]:hover:bg-[var(--hover-bg)] [@media(hover:hover)]:hover:[&_svg]:text-[var(--icon-active)]",
        secondary:
          "border-[var(--border-secondary)] bg-[var(--surface-secondary)] text-[var(--text-primary)] aria-expanded:bg-[var(--active-bg)] [&_svg]:text-[var(--icon)] [@media(hover:hover)]:hover:bg-[var(--hover-bg)] [@media(hover:hover)]:hover:[&_svg]:text-[var(--icon-active)]",
        ghost:
          "text-[var(--text-primary)] aria-expanded:bg-[var(--active-bg)] [&_svg]:text-[var(--icon)] [@media(hover:hover)]:hover:bg-[var(--hover-bg)] [@media(hover:hover)]:hover:[&_svg]:text-[var(--icon-active)]",
        destructive:
          "bg-[var(--danger)] text-[var(--danger-foreground)] focus-visible:border-[var(--danger)] focus-visible:ring-[var(--danger)] [&_svg]:text-[var(--danger-foreground)] [@media(hover:hover)]:hover:opacity-90",
        link: "text-[var(--primary)] underline-offset-4 [&_svg]:text-[var(--primary)] [@media(hover:hover)]:hover:underline",
      },
      size: {
        default:
          "h-8 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
        xs: "h-6 gap-1 rounded-[var(--radius-small)] px-2 text-xs in-data-[slot=button-group]:rounded-[var(--radius-default)] has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-7 gap-1 rounded-[var(--radius-default)] px-2.5 text-[0.8rem] in-data-[slot=button-group]:rounded-[var(--radius-default)] has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3.5",
        lg: "h-10 gap-1.5 px-3.5 has-data-[icon=inline-end]:pr-3 has-data-[icon=inline-start]:pl-3",
        icon: "size-8",
        "icon-xs":
          "size-6 rounded-[var(--radius-small)] in-data-[slot=button-group]:rounded-[var(--radius-default)] [&_svg:not([class*='size-'])]:size-3",
        "icon-sm":
          "size-7 rounded-[var(--radius-default)] in-data-[slot=button-group]:rounded-[var(--radius-default)]",
        "icon-lg": "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  ...props
}: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return (
    <ButtonPrimitive
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
