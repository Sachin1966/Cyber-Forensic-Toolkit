import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ThreatMeter } from "./ThreatMeter";
import { CheckCircle, AlertTriangle, XCircle, Clock, Hash } from "lucide-react";
import { motion } from "framer-motion";

interface ResultPanelProps {
  title: string;
  threatScore: number;
  status: "safe" | "warning" | "danger";
  timestamp: string;
  details: {
    label: string;
    value: string | number | boolean;
    type?: "text" | "hash" | "badge" | "list";
  }[];
  highlights?: string[];
}

export function ResultPanel({
  title,
  threatScore,
  status,
  timestamp,
  details,
  highlights,
}: ResultPanelProps) {
  const statusConfig = {
    safe: {
      icon: CheckCircle,
      label: "Safe",
      variant: "safe" as const,
      cardVariant: "success" as const,
    },
    warning: {
      icon: AlertTriangle,
      label: "Warning",
      variant: "warning" as const,
      cardVariant: "warning" as const,
    },
    danger: {
      icon: XCircle,
      label: "Critical",
      variant: "danger" as const,
      cardVariant: "danger" as const,
    },
  };

  const config = statusConfig[status];
  const StatusIcon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5 }}
    >
      <Card variant={config.cardVariant} className="overflow-hidden">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <StatusIcon
                className={cn(
                  "w-6 h-6",
                  status === "safe" && "text-success",
                  status === "warning" && "text-warning",
                  status === "danger" && "text-destructive"
                )}
              />
              <CardTitle className="text-xl">{title}</CardTitle>
            </div>
            <Badge variant={config.variant}>{config.label}</Badge>
          </div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground mt-2">
            <Clock className="w-4 h-4" />
            <span>{new Date(timestamp).toLocaleString()}</span>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Threat Score */}
          <div className="flex justify-center py-4">
            <ThreatMeter score={threatScore} size="lg" />
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {details.map((detail, idx) => (
              <motion.div
                key={detail.label}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.1 }}
                className="p-4 rounded-lg bg-muted/30 border border-border"
              >
                <span className="text-xs text-muted-foreground uppercase tracking-wider">
                  {detail.label}
                </span>
                <div className="mt-2">
                  {detail.type === "hash" ? (
                    <div className="flex items-center gap-2">
                      <Hash className="w-4 h-4 text-primary" />
                      <code className="text-sm font-mono text-foreground break-all">
                        {String(detail.value)}
                      </code>
                    </div>
                  ) : detail.type === "badge" ? (
                    <Badge
                      variant={
                        detail.value === true || detail.value === "Yes"
                          ? "danger"
                          : "safe"
                      }
                    >
                      {String(detail.value)}
                    </Badge>
                  ) : detail.type === "list" && Array.isArray(detail.value) ? (
                    <div className="flex flex-wrap gap-2">
                      {(detail.value as string[]).map((item, i) => (
                        <Badge key={i} variant="cyber">
                          {item}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-lg font-medium text-foreground">
                      {typeof detail.value === "boolean"
                        ? detail.value
                          ? "Yes"
                          : "No"
                        : detail.value}
                    </span>
                  )}
                </div>
              </motion.div>
            ))}
          </div>

          {/* Highlights */}
          {highlights && highlights.length > 0 && (
            <div className="p-4 rounded-lg bg-destructive/5 border border-destructive/20">
              <span className="text-sm font-medium text-destructive">
                Suspicious Elements Detected:
              </span>
              <div className="flex flex-wrap gap-2 mt-3">
                {highlights.map((item, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: idx * 0.05 }}
                  >
                    <Badge variant="danger">{item}</Badge>
                  </motion.div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
