import { cn } from "@/lib/utils";
import { motion } from "framer-motion";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  text?: string;
  className?: string;
}

export function LoadingSpinner({
  size = "md",
  text = "Analyzing...",
  className,
}: LoadingSpinnerProps) {
  const sizes = {
    sm: { container: "w-8 h-8", ring: "w-8 h-8 border-2", text: "text-sm" },
    md: { container: "w-16 h-16", ring: "w-16 h-16 border-3", text: "text-base" },
    lg: { container: "w-24 h-24", ring: "w-24 h-24 border-4", text: "text-lg" },
  };

  return (
    <div className={cn("flex flex-col items-center justify-center gap-4", className)}>
      <div className={cn("relative", sizes[size].container)}>
        {/* Outer ring */}
        <motion.div
          className={cn(
            "absolute inset-0 rounded-full border-primary/20",
            sizes[size].ring
          )}
        />
        
        {/* Spinning ring */}
        <motion.div
          className={cn(
            "absolute inset-0 rounded-full border-transparent border-t-primary border-r-primary/50",
            sizes[size].ring
          )}
          animate={{ rotate: 360 }}
          transition={{
            duration: 1,
            repeat: Infinity,
            ease: "linear",
          }}
        />

        {/* Inner glow */}
        <motion.div
          className="absolute inset-2 rounded-full bg-primary/10"
          animate={{
            scale: [1, 1.1, 1],
            opacity: [0.5, 1, 0.5],
          }}
          transition={{
            duration: 1.5,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        />

        {/* Center dot */}
        <motion.div
          className="absolute inset-0 m-auto w-2 h-2 rounded-full bg-primary"
          animate={{
            boxShadow: [
              "0 0 10px hsl(var(--primary))",
              "0 0 20px hsl(var(--primary))",
              "0 0 10px hsl(var(--primary))",
            ],
          }}
          transition={{
            duration: 1,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        />
      </div>

      {text && (
        <motion.span
          className={cn("font-medium text-muted-foreground", sizes[size].text)}
          animate={{ opacity: [0.5, 1, 0.5] }}
          transition={{
            duration: 1.5,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        >
          {text}
        </motion.span>
      )}
    </div>
  );
}
