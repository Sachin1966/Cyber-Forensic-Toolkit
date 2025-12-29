import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { api } from "@/lib/api";
import {
  FileText,
  Download,
  Search,
  Calendar,
  Filter,
  Globe,
  Mail,
  FileCode,
  Network,
  Clock,
  ChevronRight,
} from "lucide-react";

interface ReportItem {
  id: string;
  type: "url" | "email" | "file" | "pcap";
  name: string;
  threatScore: number;
  status: "safe" | "warning" | "danger";
  timestamp: string;
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

export default function Reports() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [dateRange, setDateRange] = useState<{ start: string; end: string }>({ start: "", end: "" });
  const [generating, setGenerating] = useState<string | null>(null);

  const fetchReports = async () => {
    setLoading(true);
    try {
      const data = await api.getReports({
        search: searchQuery,
        type: typeFilter !== "all" ? typeFilter : undefined,
        startDate: dateRange.start,
        endDate: dateRange.end,
      });
      // Map API response to ReportItem if needed, but they should match mostly
      // API returns ActivityItem which has id, type, name, result, threatScore, timestamp
      // ReportItem has id, type, name, threatScore, status, timestamp
      // result maps to status

      const mapped: ReportItem[] = data.map((item: any) => ({
        id: item.id,
        type: item.type,
        name: item.name,
        threatScore: item.threatScore,
        status: item.result === 'danger' ? 'danger' : item.result === 'warning' ? 'warning' : 'safe',
        timestamp: item.timestamp
      }));

      setReports(mapped);
    } catch (error) {
      console.error("Failed to fetch reports:", error);
      toast.error("Failed to load reports");
    } finally {
      setLoading(false);
    }
  };

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchReports();
    }, 500);
    return () => clearTimeout(timer);
  }, [searchQuery, typeFilter, dateRange]);

  const navigate = useNavigate();

  const handleExportAll = async () => {
    try {
      const blob = await api.exportReports();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reports_export_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success("All reports exported successfully");
    } catch (error) {
      toast.error("Failed to export reports");
      console.error(error);
    }
  };

  const handleGenerateReport = async (reportId: string) => {
    setGenerating(reportId);
    try {
      const blob = await api.generateReport(reportId);

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `forensic_report_${reportId}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast.success("Report generated successfully");
    } catch (error) {
      toast.error("Failed to generate report");
      console.error(error);
    } finally {
      setGenerating(null);
    }
  };

  const formatDate = (timestamp: string) => {
    return new Date(timestamp).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-display font-bold text-foreground flex items-center gap-3">
            <FileText className="w-8 h-8 text-primary" />
            Reports
          </h1>
          <p className="text-muted-foreground mt-1">
            View and export forensic analysis reports
          </p>
        </div>
        <Button variant="cyber" onClick={handleExportAll}>
          <Download className="w-4 h-4 mr-2" />
          Export All
        </Button>
      </motion.div>

      {/* Search & Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card variant="cyber">
          <CardContent className="pt-6">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  variant="cyber"
                  placeholder="Search reports by name or ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-12"
                />
              </div>
              <div className="flex gap-2">
                <div className="flex items-center gap-2">
                  <Input
                    type="date"
                    className="w-auto"
                    value={dateRange.start}
                    onChange={(e) => setDateRange(prev => ({ ...prev, start: e.target.value }))}
                  />
                  <span className="text-muted-foreground">-</span>
                  <Input
                    type="date"
                    className="w-auto"
                    value={dateRange.end}
                    onChange={(e) => setDateRange(prev => ({ ...prev, end: e.target.value }))}
                  />
                </div>
                <select
                  className="bg-background border border-input rounded-md px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                >
                  <option value="all">All Types</option>
                  <option value="url">URL</option>
                  <option value="email">Email</option>
                  <option value="file">File</option>
                  <option value="pcap">PCAP</option>
                </select>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Reports List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="space-y-4"
      >

        {loading ? (
          <div className="text-center py-12 text-muted-foreground">Loading reports...</div>
        ) : (
          reports.map((report, idx) => {
            const Icon = typeIcons[report.type];
            return (
              <motion.div
                key={report.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.05 }}
              >
                <Card
                  variant="cyber"
                  className="hover:border-primary/40 transition-colors cursor-pointer"
                >
                  <CardContent className="p-4">
                    <div className="flex items-center gap-4">
                      {/* Icon */}
                      <div
                        className={`w-12 h-12 rounded-lg bg-muted/50 flex items-center justify-center ${typeColors[report.type]}`}
                      >
                        <Icon className="w-6 h-6" />
                      </div>

                      {/* Info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm text-muted-foreground">
                            {report.id}
                          </span>
                          <Badge
                            variant={report.status}
                            className="text-xs"
                          >
                            {report.status === "safe"
                              ? "Safe"
                              : report.status === "warning"
                                ? "Warning"
                                : "Critical"}
                          </Badge>
                        </div>
                        <p className="font-medium text-foreground truncate mt-1">
                          {report.name}
                        </p>
                        <div className="flex items-center gap-4 mt-2 text-sm text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {formatDate(report.timestamp)}
                          </span>
                          <span>
                            Threat Score:{" "}
                            <span
                              className={
                                report.threatScore > 60
                                  ? "text-destructive"
                                  : report.threatScore > 30
                                    ? "text-warning"
                                    : "text-success"
                              }
                            >
                              {report.threatScore}%
                            </span>
                          </span>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleGenerateReport(report.id)}
                          disabled={generating === report.id}
                        >
                          <Download className="w-4 h-4 mr-2" />
                          {generating === report.id ? "Generating..." : "PDF"}
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => navigate(`/reports/${report.id}`)}>
                          <ChevronRight className="w-5 h-5" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })
        )}
      </motion.div>

      {/* Empty State */}
      {!loading && reports.length === 0 && (
        <div className="text-center py-12">
          <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">No reports found</p>
        </div>
      )}

      {/* Report Info */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card variant="cyber">
          <CardHeader>
            <CardTitle className="text-base">Report Contents</CardTitle>
            <CardDescription>
              Each PDF report includes the following information
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                "Evidence ID & Hashes",
                "Prediction Results",
                "Threat Score Analysis",
                "Feature Extraction",
                "Timeline Data",
                "Risk Indicators",
                "Recommendations",
                "Technical Details",
              ].map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 text-sm text-muted-foreground"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                  {item}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
