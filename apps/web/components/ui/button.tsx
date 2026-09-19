import { Button as ButtonPrimitive } from "@base-ui/react/button"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "cn"

const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center rounded-[var(--radius-default)] border border-transparent bg-clip-padding text-sm font-medium whitespace-nowrap transition-all outline-none select-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)] active:not-aria-[haspopup]:translate-y-px disabled:pointer-events-none disabled:opacity-50 aria-invalid:border-[var(--danger)] aria-invalid:ring-3 aria-invalid:ring-[var(--danger)] [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "bg-[var(--primary)] text-[var(--primary-foreground)] shadow-[var(--fancy-shadow-primary)] hover:opacity-90",
        outline:
          "border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)] shadow-[var(--fancy-shadow-basic)] hover:bg-[var(--hover-bg)] aria-expanded:bg-[var(--active-bg)]",
        secondary:
          "bg-[var(--button-fill)] text-[var(--surface)] shadow-[var(--fancy-shadow-neutral)] hover:opacity-90 aria-expanded:opacity-90",
        ghost:
          "text-[var(--text-primary)] hover:bg-[var(--hover-bg)] aria-expanded:bg-[var(--active-bg)]",
        destructive:
          "bg-[var(--danger)] text-[var(--danger-foreground)] shadow-[var(--fancy-shadow-destructive)] hover:opacity-90 focus-visible:border-[var(--danger)] focus-visible:ring-[var(--danger)]",
        link: "text-[var(--primary)] underline-offset-4 hover:underline",
      },
      size: {
        default:
          "h-8 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
        xs: "h-6 gap-1 rounded-[var(--radius-small)] px-2 text-xs in-data-[slot=button-group]:rounded-[var(--radius-default)] has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-7 gap-1 rounded-[var(--radius-default)] px-2.5 text-[0.8rem] in-data-[slot=button-group]:rounded-[var(--radius-default)] has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3.5",
        lg: "h-9 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
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
