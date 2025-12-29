import { cn } from "@/lib/utils";
import { motion } from "framer-motion";

interface ThreatMeterProps {
  score: number;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  animated?: boolean;
}

export function ThreatMeter({
  score,
  size = "md",
  showLabel = true,
  animated = true,
}: ThreatMeterProps) {
  const getColor = () => {
    if (score <= 30) return "text-success";
    if (score <= 60) return "text-warning";
    return "text-destructive";
  };

  const getStatus = () => {
    if (score <= 30) return "Safe";
    if (score <= 60) return "Warning";
    return "Critical";
  };

  const getGlowColor = () => {
    if (score <= 30) return "shadow-[0_0_30px_hsl(var(--success)/0.5)]";
    if (score <= 60) return "shadow-[0_0_30px_hsl(var(--warning)/0.5)]";
    return "shadow-[0_0_30px_hsl(var(--destructive)/0.5)]";
  };

  const sizes = {
    sm: { container: "w-24 h-24", text: "text-2xl", label: "text-xs" },
    md: { container: "w-36 h-36", text: "text-4xl", label: "text-sm" },
    lg: { container: "w-48 h-48", text: "text-5xl", label: "text-base" },
  };

  const radius = size === "sm" ? 40 : size === "md" ? 60 : 80;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={cn("relative flex items-center justify-center", sizes[size].container)}>
      {/* Background circle */}
      <svg className="absolute inset-0 w-full h-full -rotate-90">
        <circle
          cx="50%"
          cy="50%"
          r={radius}
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth={size === "sm" ? 6 : 8}
        />
        {/* Progress circle */}
        <motion.circle
          cx="50%"
          cy="50%"
          r={radius}
          fill="none"
          stroke={`hsl(var(${score <= 30 ? "--success" : score <= 60 ? "--warning" : "--destructive"}))`}
          strokeWidth={size === "sm" ? 6 : 8}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: animated ? strokeDashoffset : strokeDashoffset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          className={cn(getGlowColor())}
        />
      </svg>

      {/* Center content */}
      <div className="relative flex flex-col items-center justify-center">
        <motion.span
          className={cn("font-display font-bold", sizes[size].text, getColor())}
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.5 }}
        >
          {score}
        </motion.span>
        {showLabel && (
          <motion.span
            className={cn("font-medium uppercase tracking-wider", sizes[size].label, getColor())}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.8 }}
          >
            {getStatus()}
          </motion.span>
        )}
      </div>
    </div>
  );
}
