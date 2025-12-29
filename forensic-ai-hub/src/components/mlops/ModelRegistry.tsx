
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Database, FileCode, Clock, HardDrive, BarChart2 } from "lucide-react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";

interface RegistryProps {
    models: any[];
}

export const ModelRegistry = ({ models }: RegistryProps) => {
    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    Model Registry
                </CardTitle>
                <CardDescription>Production ready models and versions (Local File Store)</CardDescription>
            </CardHeader>
            <CardContent>
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead>Model Name</TableHead>
                            <TableHead>Version</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Last Updated</TableHead>
                            <TableHead>Size</TableHead>
                            <TableHead>Actions</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {models.map((model) => (
                            <TableRow key={model.name}>
                                <TableCell className="font-medium flex items-center gap-2">
                                    <FileCode className="h-4 w-4 text-muted-foreground" />
                                    {model.name}
                                </TableCell>
                                <TableCell>{model.version}</TableCell>
                                <TableCell>
                                    <Badge variant={model.status === 'Production' ? 'default' : 'destructive'} className={model.status === 'Production' ? "bg-green-500/10 text-green-500 hover:bg-green-500/20" : ""}>
                                        {model.status}
                                    </Badge>
                                </TableCell>
                                <TableCell>{model.last_updated}</TableCell>
                                <TableCell>{model.size}</TableCell>
                                <TableCell>
                                    <Dialog>
                                        <DialogTrigger asChild>
                                            <Button variant="outline" size="sm" className="h-8">Details</Button>
                                        </DialogTrigger>
                                        <DialogContent className="sm:max-w-[425px]">
                                            <DialogHeader>
                                                <DialogTitle>{model.name} Metadata</DialogTitle>
                                                <DialogDescription>
                                                    Detailed performance metrics and file information.
                                                </DialogDescription>
                                            </DialogHeader>
                                            <div className="grid gap-4 py-4">
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div className="space-y-2 p-3 bg-muted/50 rounded-lg">
                                                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                                            <BarChart2 className="h-4 w-4" /> Accuracy
                                                        </div>
                                                        <p className="text-xl font-bold">{model.accuracy || "N/A"}</p>
                                                    </div>
                                                    <div className="space-y-2 p-3 bg-muted/50 rounded-lg">
                                                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                                            <ActivityIcon className="h-4 w-4" /> Precision
                                                        </div>
                                                        <p className="text-xl font-bold">{model.precision || "N/A"}</p>
                                                    </div>
                                                </div>

                                                <div className="space-y-3 mt-2">
                                                    <h4 className="text-sm font-medium">System Info</h4>
                                                    <div className="flex justify-between text-sm">
                                                        <span className="text-muted-foreground flex items-center gap-1"><HardDrive className="h-3 w-3" /> File Size</span>
                                                        <span>{model.size}</span>
                                                    </div>
                                                    <div className="flex justify-between text-sm">
                                                        <span className="text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" /> Last Updated</span>
                                                        <span>{model.last_updated}</span>
                                                    </div>
                                                    <div className="flex justify-between text-sm">
                                                        <span className="text-muted-foreground flex items-center gap-1"><FileCode className="h-3 w-3" /> Filename</span>
                                                        <span className="font-mono text-xs">{model.filename}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        </DialogContent>
                                    </Dialog>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </CardContent>
        </Card>
    );
};

const ActivityIcon = ({ className }: { className?: string }) => (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>
);
