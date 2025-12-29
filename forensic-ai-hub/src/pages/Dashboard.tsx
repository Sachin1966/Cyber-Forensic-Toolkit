import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { StatCard } from "@/components/shared/StatCard";
import { ThreatChart } from "@/components/charts/ThreatChart";
import { ActivityTimeline } from "@/components/charts/ActivityTimeline";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { api, type DashboardStats } from "@/lib/api";
import { LoadingSpinner } from "@/components/shared/LoadingSpinner";
import {
  Shield,
  AlertTriangle,
  Globe,
  Mail,
  FileCode,
  Network,
  Activity,
  Zap,
} from "lucide-react";

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await api.getDashboardStats();
        setStats(data);
      } catch (error) {
        console.error("Failed to fetch dashboard stats:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <LoadingSpinner size="lg" text="Loading Dashboard..." />
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <p className="text-muted-foreground">Failed to load dashboard data</p>
      </div>
    );
  }

  const detectionRate = ((stats.maliciousDetected / stats.totalScans) * 100).toFixed(1);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-display font-bold text-foreground">
            Security Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time threat monitoring and analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="safe" className="px-3 py-1">
            <Activity className="w-3 h-3 mr-1" />
            System Online
          </Badge>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={stats.totalScans.toLocaleString()}
          subtitle="All time analyses"
          icon={Shield}
          variant="primary"
          trend={{ value: 12, isPositive: true }}
        />
        <StatCard
          title="Threats Detected"
          value={stats.maliciousDetected}
          subtitle={`${detectionRate}% detection rate`}
          icon={AlertTriangle}
          variant="danger"
        />
        <StatCard
          title="URLs Analyzed"
          value={stats.urlsAnalyzed}
          subtitle="Phishing detection"
          icon={Globe}
          variant="primary"
        />
        <StatCard
          title="Files Scanned"
          value={stats.filesAnalyzed}
          subtitle="Malware analysis"
          icon={FileCode}
          variant="warning"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ThreatChart data={stats.threatTrend} />
        </div>
        <ActivityTimeline activities={stats.recentActivity} />
      </div>

      {/* Bottom Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          title="Emails Analyzed"
          value={stats.emailsAnalyzed}
          subtitle="Spam & phishing detection"
          icon={Mail}
          variant="success"
        />
        <StatCard
          title="PCAP Files"
          value={stats.pcapsAnalyzed}
          subtitle="Network traffic analysis"
          icon={Network}
          variant="primary"
        />
        <Card variant="cyber">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Zap className="w-4 h-4 text-primary" />
              System Performance
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-muted-foreground">CPU Usage</span>
                <span className="text-foreground font-medium">24%</span>
              </div>
              <Progress value={24} variant="cyber" indicatorColor="gradient" />
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-muted-foreground">Memory</span>
                <span className="text-foreground font-medium">58%</span>
              </div>
              <Progress value={58} variant="cyber" indicatorColor="gradient" />
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-muted-foreground">Model Accuracy</span>
                <span className="text-foreground font-medium">94%</span>
              </div>
              <Progress value={94} variant="cyber" indicatorColor="safe" />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
