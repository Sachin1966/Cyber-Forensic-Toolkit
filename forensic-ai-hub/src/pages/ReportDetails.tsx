import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
    ArrowLeft, Download, Shield, AlertTriangle, CheckCircle,
    FileText, Globe, Mail, FileCode, Network, Activity
} from "lucide-react";
import { Loader2 } from "lucide-react";

export default function ReportDetails() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const [report, setReport] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [generatingPdf, setGeneratingPdf] = useState(false);

    useEffect(() => {
        const fetchDetails = async () => {
            if (!id) return;
            try {
                const data = await api.getReportDetails(id);
                setReport(data);
            } catch (error) {
                console.error("Failed to load report", error);
                toast.error("Failed to load report details");
            } finally {
                setLoading(false);
            }
        };
        fetchDetails();
    }, [id]);

    const handleDownloadPdf = async () => {
        if (!id) return;
        setGeneratingPdf(true);
        try {
            const blob = await api.generateReport(id);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `forensic_report_${id}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            toast.success("PDF Downloaded");
        } catch (error) {
            toast.error("Failed to download PDF");
        } finally {
            setGeneratingPdf(false);
        }
    };

    if (loading) {
        return (
            <div className="flex h-[50vh] items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
        );
    }

    if (!report) {
        return <div className="text-center py-10">Report not found</div>;
    }

    const details = report.details || {};
    const isThreat = report.is_threat;
    const score = report.confidence || 0;

    return (
        <div className="space-y-6 pb-10">
            {/* Header / Nav */}
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
                    <ArrowLeft className="w-5 h-5" />
                </Button>
                <div>
                    <h1 className="text-2xl font-display font-bold">Report Details</h1>
                    <p className="text-muted-foreground text-sm">ID: {report.id} • {new Date(report.timestamp).toLocaleString()}</p>
                </div>
                <div className="ml-auto">
                    <Button variant="cyber" onClick={handleDownloadPdf} disabled={generatingPdf}>
                        {generatingPdf ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Download className="w-4 h-4 mr-2" />}
                        Export PDF
                    </Button>
                </div>
            </div>

            {/* Top Summary Card */}
            <Card variant="cyber" className="border-l-4" style={{ borderLeftColor: isThreat ? 'var(--destructive)' : 'var(--success)' }}>
                <CardContent className="p-6">
                    <div className="flex flex-col md:flex-row gap-6 items-start md:items-center">
                        <div className={`p-4 rounded-xl ${isThreat ? 'bg-destructive/10 text-destructive' : 'bg-success/10 text-success'}`}>
                            {isThreat ? <AlertTriangle className="w-8 h-8" /> : <CheckCircle className="w-8 h-8" />}
                        </div>
                        <div className="flex-1">
                            <h2 className="text-lg font-semibold">{report.input_summary}</h2>
                            <div className="flex items-center gap-3 mt-2">
                                <Badge variant={isThreat ? 'danger' : 'safe'}>{report.prediction}</Badge>
                                <Badge variant="outline" className="uppercase">{report.scan_type}</Badge>
                            </div>
                        </div>
                        <div className="text-right">
                            <div className="text-3xl font-bold font-mono">
                                {typeof score === 'number' ? score.toFixed(1) : score}%
                            </div>
                            <div className="text-xs text-muted-foreground uppercase tracking-widest">Threat Score</div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Detailed Grids */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                {/* 1. Metadata / Info */}
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Activity className="w-5 h-5 text-primary" /> Analysis Metadata
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2 text-sm font-mono">
                        <div className="flex justify-between border-b border-border/50 pb-2">
                            <span className="text-muted-foreground">Scan Type</span>
                            <span>{report.scan_type}</span>
                        </div>
                        <div className="flex justify-between border-b border-border/50 pb-2">
                            <span className="text-muted-foreground">Prediction</span>
                            <span>{report.prediction}</span>
                        </div>
                        <div className="flex justify-between border-b border-border/50 pb-2">
                            <span className="text-muted-foreground">Confidence</span>
                            <span>{score}%</span>
                        </div>
                        <div className="flex justify-between border-b border-border/50 pb-2">
                            <span className="text-muted-foreground">Timestamp</span>
                            <span>{report.timestamp}</span>
                        </div>
                    </CardContent>
                </Card>

                {/* 2. Specific Feature Details Based on Type */}

                {/* URL Features */}
                {report.scan_type === 'url' && (
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2"><Globe className="w-5 h-5 text-primary" /> URL Features</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2 text-sm">
                            {details.features && Object.entries(details.features).map(([key, value]) => (
                                <div key={key} className="flex justify-between border-b border-border/50 pb-1 last:border-0">
                                    <span className="text-muted-foreground capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                                    <span className={value ? "text-destructive font-bold" : "text-muted-foreground"}>{String(value)}</span>
                                </div>
                            ))}
                            {!details.features && <p className="text-muted-foreground">No specific features logged.</p>}
                        </CardContent>
                    </Card>
                )}

                {/* Email Features */}
                {report.scan_type === 'email' && (
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2"><Mail className="w-5 h-5 text-primary" /> Email Analysis</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4 text-sm">
                            <div>
                                <span className="block text-muted-foreground mb-1">Subject</span>
                                <div className="p-2 bg-muted/50 rounded break-words">{details.subject || 'N/A'}</div>
                            </div>
                            <div>
                                <span className="block text-muted-foreground mb-1">Sender Reputation</span>
                                <Badge variant="outline">{details.senderReputation || 'Unknown'}</Badge>
                            </div>
                            <div>
                                <span className="block text-muted-foreground mb-1">Suspicious Terms</span>
                                {details.suspiciousTerms?.length > 0 ? (
                                    <div className="flex flex-wrap gap-2">
                                        {details.suspiciousTerms.map((term: string, i: number) => (
                                            <Badge key={i} variant="secondary">{term}</Badge>
                                        ))}
                                    </div>
                                ) : <span className="text-muted-foreground italic">None found</span>}
                            </div>
                        </CardContent>
                    </Card>
                )}

                {/* File Features */}
                {report.scan_type === 'file' && (
                    <Card className="col-span-1 md:col-span-2">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2"><FileCode className="w-5 h-5 text-primary" /> File Analysis</CardTitle>
                        </CardHeader>
                        <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm">
                            <div className="space-y-2">
                                <h3 className="font-semibold mb-2">Hashes</h3>
                                {details.hashes && Object.entries(details.hashes).map(([k, v]) => (
                                    <div key={k}>
                                        <span className="text-[10px] uppercase text-muted-foreground">{k}</span>
                                        <div className="font-mono text-xs bg-muted/50 p-1 rounded break-all">{String(v)}</div>
                                    </div>
                                ))}
                            </div>
                            <div className="space-y-2">
                                <h3 className="font-semibold mb-2">Structure</h3>
                                <div className="flex justify-between">
                                    <span className="text-muted-foreground">Size</span>
                                    <span>{details.size} bytes</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-muted-foreground">Type</span>
                                    <span>{details.type}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-muted-foreground">Entropy</span>
                                    <span>{details.metadata?.entropy?.toFixed(3) ?? 'N/A'}</span>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                )}

                {/* PCAP Features */}
                {report.scan_type === 'pcap' && (
                    <Card className="col-span-1 md:col-span-2">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2"><Network className="w-5 h-5 text-primary" /> Network Packet Analysis</CardTitle>
                        </CardHeader>
                        <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm">
                            <div className="space-y-2">
                                <h3 className="font-semibold mb-2">Traffic Stats</h3>
                                <div className="flex justify-between border-b pb-1">
                                    <span className="text-muted-foreground">Total Packets</span>
                                    <span>{details.packetCount}</span>
                                </div>
                                <div className="flex justify-between border-b pb-1">
                                    <span className="text-muted-foreground">Total Bytes</span>
                                    <span>{details.networkStats?.totalBytes}</span>
                                </div>
                            </div>
                            <div className="space-y-2">
                                <h3 className="font-semibold mb-2">Protocols</h3>
                                <div className="flex flex-wrap gap-2">
                                    {details.protocols && Object.entries(details.protocols).map(([p, c]) => (
                                        <Badge key={p} variant="secondary">{p}: {String(c)}</Badge>
                                    ))}
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                )}
            </div>

            {/* Raw JSON Fallback (for debugging or extra fields) */}
            <Card>
                <CardHeader><CardTitle>Raw Details</CardTitle></CardHeader>
                <CardContent>
                    <pre className="bg-muted/30 p-4 rounded-lg overflow-x-auto text-xs font-mono">
                        {JSON.stringify(details, null, 2)}
                    </pre>
                </CardContent>
            </Card>
        </div>
    );
}
