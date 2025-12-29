
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Activity, Server, Cpu, HardDrive, GitBranch, Database } from "lucide-react";

interface HealthProps {
    health: {
        mlflow: string;
        dvc: string;
        backend: string;
        disk_usage: string;
        cpu_usage?: string;
        ram_usage?: string;
    };
    dvcStatus?: string;
}

export const SystemHealth = ({ health, dvcStatus }: HealthProps) => {
    const getStatusColor = (status: string) => {
        if (!status) return 'text-gray-400';
        return status === 'Healthy' || status === 'Online' || status === 'Active' ? 'text-green-500' : 'text-red-500';
    };

    return (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <Card>
                <CardContent className="pt-6 flex flex-col items-center">
                    <Activity className={`h-8 w-8 mb-2 ${getStatusColor(health?.mlflow)}`} />
                    <span className="text-sm font-medium">MLflow</span>
                    <span className="text-xs text-muted-foreground">{health?.mlflow || 'Unknown'}</span>
                </CardContent>
            </Card>
            <Card>
                <CardContent className="pt-6 flex flex-col items-center">
                    <Server className={`h-8 w-8 mb-2 ${getStatusColor(health?.backend)}`} />
                    <span className="text-sm font-medium">Backend API</span>
                    <span className="text-xs text-muted-foreground">{health?.backend || 'Unknown'}</span>
                </CardContent>
            </Card>
            <Card>
                <CardContent className="pt-6 flex flex-col items-center">
                    <GitBranch className={`h-8 w-8 mb-2 ${getStatusColor(health?.dvc)}`} />
                    <span className="text-sm font-medium">DVC Pipeline</span>
                    <span className="text-xs text-muted-foreground">{health?.dvc || 'Unknown'}</span>
                </CardContent>
            </Card>
            <Card>
                <CardContent className="pt-6 flex flex-col items-center">
                    <Cpu className="h-8 w-8 mb-2 text-blue-500" />
                    <span className="text-sm font-medium">CPU Usage</span>
                    <span className="text-xs text-muted-foreground">{health?.cpu_usage || '0%'}</span>
                </CardContent>
            </Card>
            <Card>
                <CardContent className="pt-6 flex flex-col items-center">
                    <Database className="h-8 w-8 mb-2 text-purple-500" />
                    <span className="text-sm font-medium">RAM Usage</span>
                    <span className="text-xs text-muted-foreground">{health?.ram_usage || '0%'}</span>
                </CardContent>
            </Card>
            <Card>
                <CardContent className="pt-6 flex flex-col items-center">
                    <HardDrive className="h-8 w-8 mb-2 text-amber-500" />
                    <span className="text-sm font-medium">Disk Usage</span>
                    <span className="text-xs text-muted-foreground">{health?.disk_usage || '0%'}</span>
                </CardContent>
            </Card>
        </div>
    );
};
