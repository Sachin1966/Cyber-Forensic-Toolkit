import { useState } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ResultPanel } from "@/components/shared/ResultPanel";
import { LoadingSpinner } from "@/components/shared/LoadingSpinner";
import { api, type URLAnalysis } from "@/lib/api";
import { toast } from "sonner";
import { Globe, Search, ExternalLink, Shield, AlertTriangle } from "lucide-react";

export default function URLAnalyzer() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<URLAnalysis | null>(null);

  const handleAnalyze = async () => {
    if (!url.trim()) {
      toast.error("Please enter a URL to analyze");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const analysis = await api.analyzeURL(url);
      setResult(analysis);
      toast.success("URL analysis complete");
    } catch (error) {
      toast.error("Failed to analyze URL");
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

  const recentURLs = [
    { url: "https://google.com", safe: true },
    { url: "http://login-secure.verify-now.com", safe: false },
    { url: "https://github.com", safe: true },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-display font-bold text-foreground flex items-center gap-3">
          <Globe className="w-8 h-8 text-primary" />
          URL Analyzer
        </h1>
        <p className="text-muted-foreground mt-1">
          Detect phishing and malicious URLs using AI-powered analysis
        </p>
      </motion.div>

      {/* Input Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card variant="cyber">
          <CardHeader>
            <CardTitle>Enter URL to Analyze</CardTitle>
            <CardDescription>
              Our ML model will extract features and predict if the URL is legitimate or phishing
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  variant="cyber"
                  inputSize="lg"
                  placeholder="Enter URL (e.g., https://example.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                  className="pl-12"
                />
              </div>
              <Button
                variant="cyber"
                size="lg"
                onClick={handleAnalyze}
                disabled={loading}
              >
                {loading ? "Analyzing..." : "Analyze"}
              </Button>
            </div>

            {/* Quick Examples */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm text-muted-foreground">Try:</span>
              {recentURLs.map((item, idx) => (
                <button
                  key={idx}
                  onClick={() => setUrl(item.url)}
                  className="text-sm px-3 py-1 rounded-full bg-muted/50 hover:bg-muted text-foreground transition-colors flex items-center gap-2"
                >
                  {item.safe ? (
                    <Shield className="w-3 h-3 text-success" />
                  ) : (
                    <AlertTriangle className="w-3 h-3 text-destructive" />
                  )}
                  {item.url.replace(/https?:\/\//, "").slice(0, 25)}
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Loading State */}
      {loading && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex items-center justify-center py-16"
        >
          <LoadingSpinner size="lg" text="Analyzing URL features..." />
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
            title="URL Analysis Results"
            threatScore={result.threatScore}
            status={getStatus(result.threatScore)}
            timestamp={result.timestamp}
            details={[
              { label: "URL", value: result.url },
              { label: "Classification", value: result.isPhishing ? "Phishing" : "Legitimate", type: "badge" },
              { label: "HTTPS", value: result.features.hasHTTPS ? "Yes" : "No", type: "badge" },
              { label: "Contains IP", value: result.features.hasIP ? "Yes" : "No", type: "badge" },
              { label: "URL Length", value: result.features.urlLength },
              { label: "Number of Dots", value: result.features.numDots },
              { label: "Number of Dashes", value: result.features.numDashes },
              { label: "Has @ Symbol", value: result.features.hasAtSymbol ? "Yes" : "No", type: "badge" },
            ]}
            highlights={result.features.suspiciousKeywords}
          />
        </motion.div>
      )}

      {/* Info Cards */}
      {!result && !loading && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <Card variant="cyber" className="h-full">
              <CardContent className="pt-6">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                  <Shield className="w-6 h-6 text-primary" />
                </div>
                <h3 className="font-display font-semibold text-foreground mb-2">
                  Feature Extraction
                </h3>
                <p className="text-sm text-muted-foreground">
                  Automatically extracts 20+ URL features including domain age, SSL status, and suspicious patterns
                </p>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <Card variant="cyber" className="h-full">
              <CardContent className="pt-6">
                <div className="w-12 h-12 rounded-lg bg-secondary/10 flex items-center justify-center mb-4">
                  <Search className="w-6 h-6 text-secondary" />
                </div>
                <h3 className="font-display font-semibold text-foreground mb-2">
                  ML Classification
                </h3>
                <p className="text-sm text-muted-foreground">
                  Random Forest model trained on 100k+ URLs with 94% accuracy for phishing detection
                </p>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
          >
            <Card variant="cyber" className="h-full">
              <CardContent className="pt-6">
                <div className="w-12 h-12 rounded-lg bg-warning/10 flex items-center justify-center mb-4">
                  <AlertTriangle className="w-6 h-6 text-warning" />
                </div>
                <h3 className="font-display font-semibold text-foreground mb-2">
                  Threat Scoring
                </h3>
                <p className="text-sm text-muted-foreground">
                  Real-time threat score calculation based on multiple risk factors and indicators
                </p>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      )}
    </div>
  );
}
