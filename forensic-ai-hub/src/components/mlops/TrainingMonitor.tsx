
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Terminal } from "lucide-react";
import { useEffect, useRef } from "react";

interface TrainingMonitorProps {
    logs: string[];
    isTraining: boolean;
}

export const TrainingMonitor = ({ logs, isTraining }: TrainingMonitorProps) => {
    const scrollRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to bottom
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs]);

    return (
        <Card className="col-span-1 md:col-span-2">
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Terminal className="h-5 w-5" />
                    Live Training Logs
                </CardTitle>
                <CardDescription>
                    {isTraining ? "Training in progress..." : "Waiting for next training run"}
                </CardDescription>
            </CardHeader>
            <CardContent>
                {isTraining && <Progress value={undefined} className="mb-4" />}

                <ScrollArea className="h-[300px] w-full rounded-md border bg-slate-950 p-4">
                    <div ref={scrollRef} className="font-mono text-sm text-green-400 whitespace-pre-wrap">
                        {logs.length > 0 ? logs.join('\n') : "No logs available."}
                    </div>
                </ScrollArea>
            </CardContent>
        </Card>
    );
};
