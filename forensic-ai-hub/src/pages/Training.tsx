import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { api, type TrainingStatus } from "@/lib/api";
import {
  Cpu,
  Play,
  RefreshCw,
  CheckCircle,
  Clock,
  Database,
  Zap,
  Activity,
  Globe,
  Mail,
  FileCode,
  Network,
} from "lucide-react";

interface ModelInfo {
  name: string;
  icon: typeof Globe;
  description: string;
  accuracy: number;
  lastTrained: string;
  status: "ready" | "training" | "outdated";
  key: string;
}

const initialModels: ModelInfo[] = [
  {
    name: "Phishing URL Model",
    icon: Globe,
    description: "Detects malicious and phishing URLs using extracted features",
    accuracy: 0,
    lastTrained: "Never",
    status: "outdated",
    key: "phishing"
  },
  {
    name: "Malware Detection Model",
    icon: FileCode,
    description: "Classifies files as malicious or benign based on metadata",
    accuracy: 0,
    lastTrained: "Never",
    status: "outdated",
    key: "malware"
  },
  {
    name: "Network IDS Model",
    icon: Network,
    description: "Detects network intrusions and anomalies in PCAP files",
    accuracy: 0,
    lastTrained: "Never",
    status: "outdated",
    key: "network"
  },
  {
    name: "Email Spam Model",
    icon: Mail,
    description: "Identifies spam and phishing emails using NLP",
    accuracy: 0,
    lastTrained: "Never",
    status: "outdated",
    key: "email"
  },
];

export default function Training() {
  const [trainingStatus, setTrainingStatus] = useState<TrainingStatus | null>(null);
  const [isTraining, setIsTraining] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [trainingProgress, setTrainingProgress] = useState(0);
  const [modelData, setModelData] = useState<ModelInfo[]>(initialModels);
  const [datasetStats, setDatasetStats] = useState<any[]>([]);

  useEffect(() => {
    fetchStatus();
    fetchModelData();
    fetchDatasetStats();
  }, []);

  const fetchStatus = async () => {
    try {
      const status = await api.getTrainingStatus();
      setTrainingStatus(status);
    } catch (error) {
      console.error("Failed to fetch training status:", error);
    }
  };

  const fetchModelData = async () => {
    try {
      const data = await api.getModelStatus();
      const updatedModels = initialModels.map(model => {
        const key = (model as any).key;
        if (data[key]) {
          return {
            ...model,
            accuracy: data[key].accuracy,
            lastTrained: data[key].last_trained || "Never",
            status: data[key].status === 'Ready' ? 'ready' : 'outdated'
          };
        }
        return model;
      });
      setModelData(updatedModels as ModelInfo[]);
    } catch (error) {
      console.error("Failed to fetch model status:", error);
    }
  };

  const fetchDatasetStats = async () => {
    try {
      const stats = await api.getDatasetStats();
      setDatasetStats(stats);
    } catch (error) {
      console.error("Failed to fetch dataset stats:", error);
    }
  };

  const handleStartTraining = async () => {
    setIsTraining(true);
    setTrainingProgress(0);

    // Simulate training progress
    const interval = setInterval(() => {
      setTrainingProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + Math.random() * 5; // Slower progress
      });
    }, 500);

    try {
      await api.startTraining();
      // Poll for completion or just wait a bit since backend simulates it
      // In a real app we'd poll /api/train/status

      // Wait for the simulated backend thread to finish (2s)
      await new Promise(resolve => setTimeout(resolve, 3000));

      toast.success("Training completed successfully");
      fetchStatus();
      fetchModelData();
    } catch (error) {
      toast.error("Training failed");
      console.error(error);
    } finally {
      clearInterval(interval);
      setTrainingProgress(100);
      setTimeout(() => {
        setIsTraining(false);
        setTrainingProgress(0);
      }, 1000);
    }
  };

  const handleReloadModels = async () => {
    setReloading(true);
    try {
      await api.reloadModels();
      toast.success("Models reloaded successfully");
      fetchStatus();
      fetchModelData();
    } catch (error) {
      toast.error("Failed to reload models");
      console.error(error);
    } finally {
      setReloading(false);
    }
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
            <Cpu className="w-8 h-8 text-accent" />
            Model Training
          </h1>
          <p className="text-muted-foreground mt-1">
            Train and manage machine learning models
          </p>
        </div>
        <div className="flex gap-3">
          <Button
            variant="outline"
            onClick={handleReloadModels}
            disabled={reloading || isTraining}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${reloading ? "animate-spin" : ""}`} />
            {reloading ? "Reloading..." : "Reload Models"}
          </Button>
          <Button
            variant="cyber"
            onClick={handleStartTraining}
            disabled={isTraining}
          >
            <Play className="w-4 h-4 mr-2" />
            {isTraining ? "Training..." : "Start Training"}
          </Button>
        </div>
      </motion.div>

      {/* Training Progress */}
      {isTraining && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <Card variant="cyber" className="border-primary/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary animate-pulse" />
                Training in Progress
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between text-sm mb-2">
                <span className="text-muted-foreground">Overall Progress</span>
                <span className="text-foreground font-medium">
                  {Math.min(100, Math.round(trainingProgress))}%
                </span>
              </div>
              <Progress
                value={Math.min(100, trainingProgress)}
                variant="cyber"
                indicatorColor="gradient"
              />
              <p className="text-sm text-muted-foreground">
                Training all models using datasets from /dataset folders...
              </p>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Model Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {modelData.map((model, idx) => (
          <motion.div
            key={model.name}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
          >
            <Card variant="cyber" className="h-full">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                      <model.icon className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-base">{model.name}</CardTitle>
                      <Badge
                        variant={model.status === "ready" ? "safe" : model.status === "training" ? "warning" : "danger"}
                        className="mt-1"
                      >
                        {model.status === "ready" ? (
                          <>
                            <CheckCircle className="w-3 h-3 mr-1" />
                            Ready
                          </>
                        ) : model.status === "training" ? (
                          "Training"
                        ) : (
                          "Outdated"
                        )}
                      </Badge>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  {model.description}
                </p>
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-muted/30">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Zap className="w-4 h-4" />
                      Accuracy
                    </div>
                    <p className="text-xl font-display font-bold text-success mt-1">
                      {model.accuracy}%
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/30">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Clock className="w-4 h-4" />
                      Last Trained
                    </div>
                    <p className="text-sm font-medium text-foreground mt-1">
                      {model.lastTrained === "Never" ? "Never" : new Date(model.lastTrained).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Dataset Info */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <Card variant="cyber">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="w-5 h-5 text-primary" />
              Dataset Configuration
            </CardTitle>
            <CardDescription>
              The training system automatically scans the /dataset folders
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {datasetStats.length > 0 ? (
                datasetStats.map((dataset, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg bg-muted/30 border border-border"
                  >
                    <code className="text-xs text-primary">{dataset.folder}</code>
                    <p className="text-sm font-medium text-foreground mt-1">
                      {dataset.desc}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {dataset.count}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {dataset.sections}
                    </p>
                  </div>
                ))
              ) : (
                <div className="col-span-4 text-center text-muted-foreground py-4">
                  Loading dataset statistics...
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Training Info */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <Card variant="cyber">
          <CardHeader>
            <CardTitle className="text-base">Training Pipeline</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-4">
              {[
                "1. Load CSVs from dataset folders",
                "2. Clean and preprocess labels",
                "3. Feature extraction & vectorization",
                "4. Train RandomForest models",
                "5. Save to /models directory",
                "6. Hot-reload without restart",
              ].map((step, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-muted/30"
                >
                  <span className="w-6 h-6 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-bold">
                    {idx + 1}
                  </span>
                  <span className="text-sm text-foreground">
                    {step.substring(3)}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
