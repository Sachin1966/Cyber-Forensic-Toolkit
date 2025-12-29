
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, BarChart, Bar } from 'recharts';

interface MetricsProps {
    data: any;
}

export const MetricsDashboard = ({ data }: MetricsProps) => {
    // Use history from backend, or empty array if not ready
    const efficiencyData = data?.history || [];

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
                <CardHeader>
                    <CardTitle>Training Performance</CardTitle>
                    <CardDescription>Accuracy trends over recent runs</CardDescription>
                </CardHeader>
                <CardContent className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={efficiencyData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" tick={{ fontSize: 10 }} angle={-15} textAnchor="end" height={50} />
                            <YAxis domain={[0, 100]} />
                            <Tooltip />
                            <Legend />
                            <Line type="monotone" dataKey="accuracy" stroke="#10b981" name="Accuracy (%)" />
                        </LineChart>
                    </ResponsiveContainer>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Metric Comparison</CardTitle>
                    <CardDescription>Latest metrics per model</CardDescription>
                </CardHeader>
                <CardContent className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={data?.experiments || []}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                            <YAxis domain={[0, 1]} />
                            <Tooltip />
                            <Legend />
                            <Bar dataKey="latest_run.metrics.accuracy" name="Accuracy" fill="#3b82f6" />
                            <Bar dataKey="latest_run.metrics.precision" name="Precision" fill="#8b5cf6" />
                            <Bar dataKey="latest_run.metrics.recall" name="Recall" fill="#f59e0b" />
                        </BarChart>
                    </ResponsiveContainer>
                </CardContent>
            </Card>
        </div>
    );
};
