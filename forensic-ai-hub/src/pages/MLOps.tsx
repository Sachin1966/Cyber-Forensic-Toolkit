
import { Layout } from "@/components/layout/Layout";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useQuery } from "@tanstack/react-query";
import { TrainingMonitor } from "@/components/mlops/TrainingMonitor";
import { MetricsDashboard } from "@/components/mlops/MetricsDashboard";
import { ModelRegistry } from "@/components/mlops/ModelRegistry";
import { SystemHealth } from "@/components/mlops/SystemHealth";
import { Button } from "@/components/ui/button";
import { Play, RefreshCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

// Fetch functions
const fetchLogs = async () => {
    const res = await fetch('/api/mlops/logs');
    return res.json();
};

const fetchMetrics = async () => {
    const res = await fetch('/api/mlops/metrics');
    return res.json();
};

const fetchRegistry = async () => {
    const res = await fetch('/api/mlops/registry');
    return res.json();
};

const fetchSystem = async () => {
    const res = await fetch('/api/mlops/system');
    return res.json();
};

const fetchDvc = async () => {
    const res = await fetch('/api/mlops/dvc-status');
    return res.json();
};

const MLOps = () => {
    const [isTraining, setIsTraining] = useState(false);

    // Logs: 1s polling
    const { data: logsData } = useQuery({
        queryKey: ['mlops-logs'],
        queryFn: fetchLogs,
        refetchInterval: 1000,
    });

    // Metrics & System: 3s polling
    const { data: metricsData } = useQuery({
        queryKey: ['mlops-metrics'],
        queryFn: fetchMetrics,
        refetchInterval: 3000,
    });

    const { data: systemData } = useQuery({
        queryKey: ['mlops-system'],
        queryFn: fetchSystem,
        refetchInterval: 3000,
    });

    // Registry & DVC: 10s polling
    const { data: registryData } = useQuery({
        queryKey: ['mlops-registry'],
        queryFn: fetchRegistry,
        refetchInterval: 10000,
    });

    const { data: dvcData } = useQuery({
        queryKey: ['mlops-dvc'],
        queryFn: fetchDvc,
        refetchInterval: 10000,
    });

    const handleStartTraining = async () => {
        setIsTraining(true);
        toast.info("Initializing background training pipeline...");
        try {
            const token = localStorage.getItem('access_token');
            const res = await fetch('/api/mlops/retrain', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (res.ok) {
                toast.success("Training started! Check logs tab.");
            } else {
                toast.error("Failed to start training.");
                setIsTraining(false);
            }
        } catch (e) {
            toast.error("Network error starting training");
            setIsTraining(false);
        }

        // Reset button state after delay (actual status should come from logs/API eventually)
        setTimeout(() => setIsTraining(false), 5000);
    };

    return (
        <div className="space-y-6 animate-in fade-in duration-500">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-primary to-blue-600 bg-clip-text text-transparent">MLOps Dashboard</h1>
                    <p className="text-muted-foreground mt-1">Real-time model monitoring, versioning, and system health.</p>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" size="icon" onClick={() => window.location.reload()}>
                        <RefreshCw className="h-4 w-4" />
                    </Button>
                    <Button onClick={handleStartTraining} disabled={isTraining} className="cyber-glow transition-all hover:scale-105">
                        <Play className="mr-2 h-4 w-4" />
                        {isTraining ? "Starting..." : "Start Retraining"}
                    </Button>
                </div>
            </div>

            <SystemHealth health={systemData || metricsData?.system_health} dvcStatus={dvcData?.status} />

            <Tabs defaultValue="dashboard" className="space-y-4">
                <TabsList className="bg-muted/50 p-1">
                    <TabsTrigger value="dashboard">Overview</TabsTrigger>
                    <TabsTrigger value="training">Training & Logs</TabsTrigger>
                    <TabsTrigger value="registry">Model Registry</TabsTrigger>
                    <TabsTrigger value="dvc">DVC Status</TabsTrigger>
                </TabsList>

                <TabsContent value="dashboard" className="space-y-4">
                    <MetricsDashboard data={metricsData} />
                    <ModelRegistry models={registryData?.models || []} />
                </TabsContent>

                <TabsContent value="training" className="space-y-4">
                    <TrainingMonitor logs={logsData?.logs || []} isTraining={isTraining} />
                </TabsContent>

                <TabsContent value="registry" className="space-y-4">
                    <ModelRegistry models={registryData?.models || []} />
                </TabsContent>

                <TabsContent value="dvc" className="space-y-4">
                    <div className="rounded-md border bg-slate-950 p-4 font-mono text-sm">
                        <pre className="text-blue-400">{dvcData?.status || "Checking DVC status..."}</pre>
                    </div>
                </TabsContent>
            </Tabs>
        </div>
    );
};

export default MLOps;
