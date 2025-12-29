import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Globe, Mail, FileCode, Network, ArrowRight } from "lucide-react";
import { motion } from "framer-motion";
import type { ActivityItem } from "@/lib/api";
import { useNavigate } from "react-router-dom";

interface ActivityTimelineProps {
  activities: ActivityItem[];
  title?: string;
}

const typeIcons = {
  url: Globe,
  email: Mail,
  file: FileCode,
  pcap: Network,
};

const typeColors = {
  url: "text-primary",
  email: "text-secondary",
  file: "text-cyber-orange",
  pcap: "text-cyber-purple",
};

export function ActivityTimeline({
  activities,
  title = "Recent Activity",
}: ActivityTimelineProps) {
  const navigate = useNavigate();

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);

    if (minutes < 1) return "Just now";
    if (minutes < 60) return `${minutes}m ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <Card variant="cyber" className="h-full">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-lg font-medium">{title}</CardTitle>
        <Button
          variant="ghost"
          size="sm"
          className="text-primary hover:text-primary/80 hover:bg-transparent px-0 z-10 relative"
          onClick={(e) => {
            e.stopPropagation();
            console.log("Navigating to reports");
            navigate('/reports');
          }}
        >
          View All
          <ArrowRight className="w-4 h-4 ml-1" />
        </Button>
      </CardHeader>
      <CardContent>
        <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2">
          {activities.map((activity, idx) => {
            const Icon = typeIcons[activity.type];
            return (
              <motion.div
                key={activity.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.1 }}
                onClick={() => navigate(`/reports/${activity.id}`)}
                className="flex items-start gap-4 p-3 rounded-lg hover:bg-muted/30 transition-colors cursor-pointer group"
              >
                <div
                  className={cn(
                    "w-10 h-10 rounded-lg flex items-center justify-center bg-muted/50 group-hover:bg-muted transition-colors",
                    typeColors[activity.type]
                  )}
                >
                  <Icon className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">
                    {activity.name}
                  </p>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge
                      variant={activity.result}
                      className="text-xs"
                    >
                      {activity.result === "safe"
                        ? "Safe"
                        : activity.result === "warning"
                          ? "Warning"
                          : "Critical"}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      Score: {activity.threatScore}
                    </span>
                  </div>
                </div>
                <span className="text-xs text-muted-foreground whitespace-nowrap">
                  {formatTime(activity.timestamp)}
                </span>
              </motion.div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
