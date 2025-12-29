import { useState } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { ResultPanel } from "@/components/shared/ResultPanel";
import { LoadingSpinner } from "@/components/shared/LoadingSpinner";
import { api, type EmailAnalysis } from "@/lib/api";
import { toast } from "sonner";
import { Mail, Scan, AlertTriangle, Shield, User } from "lucide-react";

export default function EmailAnalyzer() {
  const [subject, setSubject] = useState("");
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EmailAnalysis | null>(null);

  const handleAnalyze = async () => {
    if (!content.trim()) {
      toast.error("Please enter email content to analyze");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const analysis = await api.analyzeEmail(content, subject);
      setResult(analysis);
      toast.success("Email analysis complete");
    } catch (error) {
      toast.error("Failed to analyze email");
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

  const sampleEmails = [
    {
      subject: "Your account has been suspended",
      content: "URGENT: Your account will be permanently deleted unless you verify your identity immediately. Click here to verify: http://secure-bank-login.com/verify",
    },
    {
      subject: "Meeting reminder",
      content: "Hi, Just a quick reminder about our meeting tomorrow at 10 AM. Please bring your laptop. Best regards, John",
    },
    {
      subject: "You've won $1,000,000!",
      content: "Congratulations! You've been selected as the winner of our lottery. Click here to claim your prize NOW! Limited time offer. Act fast!",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-display font-bold text-foreground flex items-center gap-3">
          <Mail className="w-8 h-8 text-secondary" />
          Email Analyzer
        </h1>
        <p className="text-muted-foreground mt-1">
          Detect phishing emails and spam using natural language processing
        </p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card variant="cyber" className="h-full">
            <CardHeader>
              <CardTitle>Email Content</CardTitle>
              <CardDescription>
                Paste the email content you want to analyze for phishing or spam indicators
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground mb-2 block">
                  Subject Line
                </label>
                <Input
                  variant="cyber"
                  placeholder="Email subject..."
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground mb-2 block">
                  Email Body
                </label>
                <Textarea
                  variant="cyber"
                  placeholder="Paste the email content here..."
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  className="min-h-[200px]"
                />
              </div>
              <Button
                variant="cyber"
                size="lg"
                onClick={handleAnalyze}
                disabled={loading}
                className="w-full"
              >
                <Scan className="w-5 h-5 mr-2" />
                {loading ? "Analyzing..." : "Analyze Email"}
              </Button>
            </CardContent>
          </Card>
        </motion.div>

        {/* Sample Emails */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-4"
        >
          <h3 className="font-display font-semibold text-foreground">
            Sample Emails
          </h3>
          {sampleEmails.map((email, idx) => (
            <Card
              key={idx}
              variant="cyber"
              className="cursor-pointer hover:border-primary/50 transition-colors"
              onClick={() => {
                setSubject(email.subject);
                setContent(email.content);
              }}
            >
              <CardContent className="pt-4">
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center shrink-0">
                    <User className="w-5 h-5 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-foreground truncate">
                      {email.subject}
                    </p>
                    <p className="text-sm text-muted-foreground line-clamp-2 mt-1">
                      {email.content}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
          <p className="text-xs text-muted-foreground text-center">
            Click a sample to load it for analysis
          </p>
        </motion.div>
      </div>

      {/* Loading State */}
      {loading && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex items-center justify-center py-16"
        >
          <LoadingSpinner size="lg" text="Analyzing email content..." />
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
            title="Email Analysis Results"
            threatScore={result.threatScore}
            status={getStatus(result.threatScore)}
            timestamp={result.timestamp}
            details={[
              { label: "Subject", value: result.subject },
              { label: "Phishing Detected", value: result.isPhishing ? "Yes" : "No", type: "badge" },
              { label: "Spam Detected", value: result.isSpam ? "Yes" : "No", type: "badge" },
              { label: "Sender Reputation", value: result.senderReputation },
            ]}
            highlights={result.suspiciousTerms}
          />
        </motion.div>
      )}

      {/* Info Section */}
      {!result && !loading && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <Card variant="cyber">
              <CardContent className="pt-6">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-lg bg-destructive/10 flex items-center justify-center shrink-0">
                    <AlertTriangle className="w-6 h-6 text-destructive" />
                  </div>
                  <div>
                    <h3 className="font-display font-semibold text-foreground mb-2">
                      What We Detect
                    </h3>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      <li>• Urgency and pressure tactics</li>
                      <li>• Suspicious links and domains</li>
                      <li>• Financial scam indicators</li>
                      <li>• Impersonation attempts</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
          >
            <Card variant="cyber">
              <CardContent className="pt-6">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-lg bg-success/10 flex items-center justify-center shrink-0">
                    <Shield className="w-6 h-6 text-success" />
                  </div>
                  <div>
                    <h3 className="font-display font-semibold text-foreground mb-2">
                      How It Works
                    </h3>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      <li>• NLP-based text analysis</li>
                      <li>• Keyword pattern matching</li>
                      <li>• ML classification model</li>
                      <li>• Real-time threat scoring</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      )}
    </div>
  );
}
