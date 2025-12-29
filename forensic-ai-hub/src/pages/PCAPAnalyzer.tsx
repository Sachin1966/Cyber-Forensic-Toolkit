import { useState } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FileDropzone } from "@/components/shared/FileDropzone";
import { ResultPanel } from "@/components/shared/ResultPanel";
import { LoadingSpinner } from "@/components/shared/LoadingSpinner";
import { ProtocolChart } from "@/components/charts/ProtocolChart";
import { api, type PCAPAnalysis } from "@/lib/api";
import { toast } from "sonner";
import { Network, Scan, Activity, Wifi, Server, AlertTriangle } from "lucide-react";

export default function PCAPAnalyzer() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PCAPAnalysis | null>(null);

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      toast.error("Please select a PCAP file to analyze");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const analysis = await api.analyzePCAP(selectedFile);
      setResult(analysis);
      toast.success("PCAP analysis complete");
    } catch (error) {
      toast.error("Failed to analyze PCAP file");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const getStatus = (score: number): "safe" | "warning" | "danger" => {
    if (score <= 30) return "safe";
    if (score <= 60) return "warning";
    return "danger";
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + " KB";
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + " MB";
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
  };

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-display font-bold text-foreground flex items-center gap-3">
          <Network className="w-8 h-8 text-cyber-purple" />
          PCAP Analyzer
        </h1>
        <p className="text-muted-foreground mt-1">
          Network traffic analysis and intrusion detection
        </p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Section */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-2"
        >
          <Card variant="cyber">
            <CardHeader>
              <CardTitle>Upload PCAP File</CardTitle>
              <CardDescription>
                Upload a packet capture file for network traffic analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <FileDropzone
                onFileSelect={handleFileSelect}
                accept=".pcap,.pcapng,.cap"
                maxSize={100}
              />
              <Button
                variant="cyber"
                size="lg"
                onClick={handleAnalyze}
                disabled={!selectedFile || loading}
                className="w-full"
              >
                <Scan className="w-5 h-5 mr-2" />
                {loading ? "Analyzing..." : "Analyze PCAP"}
              </Button>
            </CardContent>
          </Card>
        </motion.div>

        {/* Analysis Features */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-4"
        >
          <h3 className="font-display font-semibold text-foreground">
            Detection Capabilities
          </h3>
          <Card variant="cyber">
            <CardContent className="pt-4 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-destructive/10 flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 text-destructive" />
                </div>
                <div>
                  <p className="font-medium text-foreground">Port Scanning</p>
                  <p className="text-xs text-muted-foreground">Detect reconnaissance</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center">
                  <Activity className="w-5 h-5 text-warning" />
                </div>
                <div>
                  <p className="font-medium text-foreground">DDoS Patterns</p>
                  <p className="text-xs text-muted-foreground">Traffic anomalies</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-secondary/10 flex items-center justify-center">
                  <Wifi className="w-5 h-5 text-secondary" />
                </div>
                <div>
                  <p className="font-medium text-foreground">Protocol Analysis</p>
                  <p className="text-xs text-muted-foreground">TCP/UDP/ICMP breakdown</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Server className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="font-medium text-foreground">IDS Model</p>
                  <p className="text-xs text-muted-foreground">ML-based detection</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Supported formats */}
          <Card variant="cyber">
            <CardContent className="pt-4">
              <p className="text-sm font-medium text-muted-foreground mb-3">
                Supported Formats
              </p>
              <div className="flex flex-wrap gap-2">
                {['PCAP', 'PCAPNG', 'CAP'].map((ext) => (
                  <Badge key={ext} variant="cyber">
                    .{ext}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Loading State */}
      {loading && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex items-center justify-center py-16"
        >
          <LoadingSpinner size="lg" text="Analyzing network traffic..." />
        </motion.div>
      )}

      {/* Results */}
      {result && !loading && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-6"
        >
          <ResultPanel
            title="PCAP Analysis Results"
            threatScore={result.threatScore}
            status={getStatus(result.threatScore)}
            timestamp={result.timestamp}
            details={[
              { label: "Filename", value: result.filename },
              { label: "Total Packets", value: result.packetCount.toLocaleString() },
              { label: "Total Traffic", value: formatBytes(result.networkStats.totalBytes) },
              { label: "Avg Packet Size", value: formatBytes(result.networkStats.avgPacketSize) },
              { label: "Capture Duration", value: formatDuration(result.networkStats.duration) },
            ]}
            highlights={result.anomalies}
          />

          {/* Protocol Distribution */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <ProtocolChart data={result.protocols} />

            <Card variant="cyber">
              <CardHeader>
                <CardTitle className="text-base">Protocol Breakdown</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {Object.entries(result.protocols).map(([protocol, count]) => (
                  <div key={protocol} className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Badge variant="cyber">{protocol}</Badge>
                      <span className="text-sm text-muted-foreground">
                        {((count / result.packetCount) * 100).toFixed(1)}%
                      </span>
                    </div>
                    <span className="font-mono text-foreground">
                      {count.toLocaleString()} packets
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Anomalies */}
          {result.anomalies.length > 0 && (
            <Card variant="danger">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-destructive" />
                  Detected Anomalies
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {result.anomalies.map((anomaly, idx) => (
                    <li key={idx} className="flex items-center gap-2 text-foreground">
                      <span className="w-2 h-2 rounded-full bg-destructive" />
                      {anomaly}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </motion.div>
      )}
    </div>
  );
}
