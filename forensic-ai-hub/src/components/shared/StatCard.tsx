import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { LucideIcon } from "lucide-react";
import { motion } from "framer-motion";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  variant?: "default" | "primary" | "success" | "warning" | "danger";
  className?: string;
}

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
  className,
}: StatCardProps) {
  const variants = {
    default: {
      iconBg: "bg-muted",
      iconColor: "text-foreground",
      glow: "",
    },
    primary: {
      iconBg: "bg-primary/10",
      iconColor: "text-primary",
      glow: "hover:shadow-[0_0_30px_hsl(var(--primary)/0.2)]",
    },
    success: {
      iconBg: "bg-success/10",
      iconColor: "text-success",
      glow: "hover:shadow-[0_0_30px_hsl(var(--success)/0.2)]",
    },
    warning: {
      iconBg: "bg-warning/10",
      iconColor: "text-warning",
      glow: "hover:shadow-[0_0_30px_hsl(var(--warning)/0.2)]",
    },
    danger: {
      iconBg: "bg-destructive/10",
      iconColor: "text-destructive",
      glow: "hover:shadow-[0_0_30px_hsl(var(--destructive)/0.2)]",
    },
  };

  const v = variants[variant];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -4 }}
      transition={{ duration: 0.3 }}
    >
      <Card
        variant="cyber"
        className={cn("hover-lift transition-all duration-300", v.glow, className)}
      >
        <CardContent className="p-6">
          <div className="flex items-start justify-between">
            <div className="flex flex-col gap-2">
              <span className="text-sm text-muted-foreground font-medium">
                {title}
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-display font-bold text-foreground">
                  {value}
                </span>
                {trend && (
                  <span
                    className={cn(
                      "text-sm font-medium",
                      trend.isPositive ? "text-success" : "text-destructive"
                    )}
                  >
                    {trend.isPositive ? "+" : "-"}
                    {Math.abs(trend.value)}%
                  </span>
                )}
              </div>
              {subtitle && (
                <span className="text-xs text-muted-foreground">{subtitle}</span>
              )}
            </div>
            <div
              className={cn(
                "w-12 h-12 rounded-xl flex items-center justify-center",
                v.iconBg
              )}
            >
              <Icon className={cn("w-6 h-6", v.iconColor)} />
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
