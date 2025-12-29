import { useState } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FileDropzone } from "@/components/shared/FileDropzone";
import { ResultPanel } from "@/components/shared/ResultPanel";
import { LoadingSpinner } from "@/components/shared/LoadingSpinner";
import { api, type FileAnalysis } from "@/lib/api";
import { toast } from "sonner";
import { FileCode, Scan, Shield, Bug, Database, Lock } from "lucide-react";

export default function FileAnalyzer() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<FileAnalysis | null>(null);

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      toast.error("Please select a file to analyze");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const analysis = await api.analyzeFile(selectedFile);
      setResult(analysis);
      toast.success("File analysis complete");
    } catch (error) {
      toast.error("Failed to analyze file");
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
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-display font-bold text-foreground flex items-center gap-3">
          <FileCode className="w-8 h-8 text-cyber-orange" />
          File Analyzer
        </h1>
        <p className="text-muted-foreground mt-1">
          Static malware analysis with metadata extraction and threat detection
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
              <CardTitle>Upload File</CardTitle>
              <CardDescription>
                Upload any file (EXE, DLL, PDF, etc.) for malware analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <FileDropzone
                onFileSelect={handleFileSelect}
                accept="*"
                maxSize={50}
              />
              <Button
                variant="cyber"
                size="lg"
                onClick={handleAnalyze}
                disabled={!selectedFile || loading}
                className="w-full"
              >
                <Scan className="w-5 h-5 mr-2" />
                {loading ? "Analyzing..." : "Analyze File"}
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
            Analysis Features
          </h3>
          <Card variant="cyber">
            <CardContent className="pt-4 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Lock className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="font-medium text-foreground">Hash Calculation</p>
                  <p className="text-xs text-muted-foreground">MD5, SHA1, SHA256</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-secondary/10 flex items-center justify-center">
                  <Bug className="w-5 h-5 text-secondary" />
                </div>
                <div>
                  <p className="font-medium text-foreground">Entropy Analysis</p>
                  <p className="text-xs text-muted-foreground">Detect packed/encrypted code</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center">
                  <Database className="w-5 h-5 text-warning" />
                </div>
                <div>
                  <p className="font-medium text-foreground">PE Analysis</p>
                  <p className="text-xs text-muted-foreground">Sections & imports</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-success" />
                </div>
                <div>
                  <p className="font-medium text-foreground">ML Classification</p>
                  <p className="text-xs text-muted-foreground">Malicious/benign prediction</p>
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
                {['EXE', 'DLL', 'PDF', 'DOC', 'XLS', 'ZIP', 'JAR', 'APK'].map((ext) => (
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
          <LoadingSpinner size="lg" text="Analyzing file metadata..." />
        </motion.div>
      )}

      {/* Results */}
      {result && !loading && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <ResultPanel
            title="File Analysis Results"
            threatScore={result.threatScore}
            status={getStatus(result.threatScore)}
            timestamp={result.timestamp}
            details={[
              { label: "Filename", value: result.filename },
              { label: "Size", value: formatBytes(result.size) },
              { label: "Type", value: result.type },
              { label: "Classification", value: result.isMalicious ? "Malicious" : "Benign", type: "badge" },
              { label: "Entropy", value: result.metadata.entropy.toFixed(2) },
              { label: "MD5", value: result.hashes.md5, type: "hash" },
              { label: "SHA1", value: result.hashes.sha1, type: "hash" },
              { label: "SHA256", value: result.hashes.sha256, type: "hash" },
            ]}
            highlights={result.isMalicious ? result.metadata.sections : []}
          />

          {/* Additional Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
            <Card variant="cyber">
              <CardHeader>
                <CardTitle className="text-base">PE Sections</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {result.metadata.sections.map((section, idx) => (
                    <Badge key={idx} variant="cyber">
                      {section}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card variant="cyber">
              <CardHeader>
                <CardTitle className="text-base">Imported DLLs</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {result.metadata.imports.map((imp, idx) => (
                    <Badge key={idx} variant="magenta">
                      {imp}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </motion.div>
      )}
    </div>
  );
}
