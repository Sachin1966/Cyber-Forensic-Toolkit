import * as React from "react";
import * as ProgressPrimitive from "@radix-ui/react-progress";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const progressVariants = cva(
  "relative h-4 w-full overflow-hidden rounded-full",
  {
    variants: {
      variant: {
        default: "bg-muted",
        cyber: "bg-muted/50 border border-primary/20",
        threat: "bg-muted/50 border border-border",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

const indicatorVariants = cva(
  "h-full w-full flex-1 transition-all duration-500",
  {
    variants: {
      indicatorColor: {
        default: "bg-primary",
        gradient: "bg-gradient-to-r from-primary to-secondary",
        threat: "bg-gradient-to-r from-success via-warning to-destructive",
        safe: "bg-success",
        warning: "bg-warning",
        danger: "bg-destructive",
      },
    },
    defaultVariants: {
      indicatorColor: "default",
    },
  }
);

export interface ProgressProps
  extends React.ComponentPropsWithoutRef<typeof ProgressPrimitive.Root>,
    VariantProps<typeof progressVariants>,
    VariantProps<typeof indicatorVariants> {}

const Progress = React.forwardRef<
  React.ElementRef<typeof ProgressPrimitive.Root>,
  ProgressProps
>(({ className, value, variant, indicatorColor, ...props }, ref) => (
  <ProgressPrimitive.Root
    ref={ref}
    className={cn(progressVariants({ variant, className }))}
    {...props}
  >
    <ProgressPrimitive.Indicator
      className={cn(indicatorVariants({ indicatorColor }))}
      style={{ transform: `translateX(-${100 - (value || 0)}%)` }}
    />
  </ProgressPrimitive.Root>
));
Progress.displayName = ProgressPrimitive.Root.displayName;

export { Progress };
