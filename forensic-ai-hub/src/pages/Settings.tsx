import { useState, useEffect } from "react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import { AlertTriangle, User, Shield, Bell, Trash2, Save, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

export default function Settings() {
    const { user, logout, updateUser } = useAuth();
    const navigate = useNavigate();
    const [isLoading, setIsLoading] = useState(false);

    // Profile State
    const [name, setName] = useState(user?.name || "");
    const [email, setEmail] = useState(user?.email || "");

    // Password State
    const [currentPassword, setCurrentPassword] = useState("");
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    // Preferences State
    const [highRiskAlerts, setHighRiskAlerts] = useState(true);
    const [mediumRiskAlerts, setMediumRiskAlerts] = useState(true);
    const [notifBadges, setNotifBadges] = useState(true);
    const [theme, setTheme] = useState("system"); // system, light, dark

    useEffect(() => {
        if (user) {
            setName(user.name);
            setEmail(user.email);

            // Fetch explicit settings if available in user object or fetch fresh
            // Since useAuth user might be stale or missing fields, let's fetch fresh
            // Actually, we can just use what we have or assume defaults if missing
            if (user.alert_preferences) {
                try {
                    const prefs = typeof user.alert_preferences === 'string'
                        ? JSON.parse(user.alert_preferences)
                        : user.alert_preferences;
                    setHighRiskAlerts(prefs.highRiskAlerts ?? true);
                    setMediumRiskAlerts(prefs.mediumRiskAlerts ?? true);
                } catch (e) { console.error("Error parsing prefs", e); }
            }
            if (user.show_badges !== undefined) {
                setNotifBadges(!!user.show_badges);
            }
            if (user.theme_preference) {
                setTheme(user.theme_preference);
            }
        }
    }, [user]);

    const handleSaveProfile = async () => {
        setIsLoading(true);
        try {
            const prefs = {
                highRiskAlerts,
                mediumRiskAlerts
            };

            const data = {
                name,
                alert_preferences: prefs,
                theme_preference: theme,
                show_badges: notifBadges
            };

            const res = await api.updateSettings(data);
            if (res.success) {
                toast.success("Settings updated successfully");
                if (res.user) {
                    updateUser(res.user);
                }
            }
        } catch (error) {
            toast.error("Failed to update settings");
            console.error(error);
        } finally {
            setIsLoading(false);
        }
    };

    const handleChangePassword = async () => {
        if (newPassword !== confirmPassword) {
            toast.error("Passwords do not match");
            return;
        }
        if (!currentPassword) {
            toast.error("Please enter current password");
            return;
        }

        setIsLoading(true);
        try {
            const res = await api.updatePassword({ currentPassword, newPassword });
            if (res.success) {
                toast.success("Password updated successfully");
                setCurrentPassword("");
                setNewPassword("");
                setConfirmPassword("");
            }
        } catch (error: any) {
            toast.error(error.message || "Failed to update password");
        } finally {
            setIsLoading(false);
        }
    };

    const handleDeleteAccount = async () => {
        setIsLoading(true);
        try {
            const res = await api.deleteAccount();
            if (res.success) {
                toast.success("Account deleted");
                logout(); // This handles navigation to login
            }
        } catch (error) {
            toast.error("Failed to delete account");
            console.error(error);
            setIsLoading(false);
        }
    };

    return (
        <div className="container py-8 space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
                <p className="text-muted-foreground mt-2">Manage your account settings and preferences.</p>
            </div>

            <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
                {/* Profile Section */}
                <div className="space-y-6 lg:col-span-2">

                    {/* General Settings */}
                    <Card>
                        <CardHeader>
                            <div className="flex items-center gap-2">
                                <User className="h-5 w-5 text-primary" />
                                <CardTitle>Profile Information</CardTitle>
                            </div>
                            <CardDescription>Update your account's profile information and email address.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid gap-2">
                                <Label htmlFor="name">Name</Label>
                                <Input id="name" value={name} onChange={(e) => setName(e.target.value)} />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="email">Email</Label>
                                <Input id="email" value={email} disabled className="bg-muted" />
                                <p className="text-xs text-muted-foreground">Email change is currently disabled.</p>
                            </div>
                        </CardContent>
                        <CardFooter className="border-t px-6 py-4 bg-muted/20">
                            <Button onClick={handleSaveProfile} disabled={isLoading}>
                                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                Save Changes
                            </Button>
                        </CardFooter>
                    </Card>

                    {/* Application Preferences */}
                    <Card>
                        <CardHeader>
                            <div className="flex items-center gap-2">
                                <Bell className="h-5 w-5 text-primary" />
                                <CardTitle>Notifications & Alerts</CardTitle>
                            </div>
                            <CardDescription>Configure how you receive alerts and notifications.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="flex items-center justify-between space-x-2">
                                <div className="space-y-0.5">
                                    <Label className="text-base">High Risk Alerts</Label>
                                    <p className="text-sm text-muted-foreground">Receive immediate emails for critical threats.</p>
                                </div>
                                <Switch checked={highRiskAlerts} onCheckedChange={setHighRiskAlerts} />
                            </div>
                            <Separator />
                            <div className="flex items-center justify-between space-x-2">
                                <div className="space-y-0.5">
                                    <Label className="text-base">Medium Risk Alerts</Label>
                                    <p className="text-sm text-muted-foreground">Receive emails for medium risk threats.</p>
                                </div>
                                <Switch checked={mediumRiskAlerts} onCheckedChange={setMediumRiskAlerts} />
                            </div>
                            <Separator />
                            <div className="flex items-center justify-between space-x-2">
                                <div className="space-y-0.5">
                                    <Label className="text-base">Notification Badges</Label>
                                    <p className="text-sm text-muted-foreground">Show red badge on bell icon for unread items.</p>
                                </div>
                                <Switch checked={notifBadges} onCheckedChange={setNotifBadges} />
                            </div>
                        </CardContent>
                        <CardFooter className="border-t px-6 py-4 bg-muted/20">
                            <Button onClick={handleSaveProfile} disabled={isLoading}>
                                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                Save Preferences
                            </Button>
                        </CardFooter>
                    </Card>
                </div>

                {/* Sidebar/Right Column */}
                <div className="space-y-6">

                    {/* Security */}
                    <Card>
                        <CardHeader>
                            <div className="flex items-center gap-2">
                                <Shield className="h-5 w-5 text-primary" />
                                <CardTitle>Security</CardTitle>
                            </div>
                            <CardDescription>Change your password.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid gap-2">
                                <Label htmlFor="current">Current Password</Label>
                                <Input id="current" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="new">New Password</Label>
                                <Input id="new" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
                            </div>
                            <div className="grid gap-2">
                                <Label htmlFor="confirm">Confirm Password</Label>
                                <Input id="confirm" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
                            </div>
                        </CardContent>
                        <CardFooter className="border-t px-6 py-4 bg-muted/20">
                            <Button onClick={handleChangePassword} disabled={isLoading} variant="outline" className="w-full">
                                {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
                                Update Password
                            </Button>
                        </CardFooter>
                    </Card>

                    {/* Danger Zone */}
                    <Card className="border-destructive/50">
                        <CardHeader>
                            <div className="flex items-center gap-2 text-destructive">
                                <AlertTriangle className="h-5 w-5" />
                                <CardTitle>Danger Zone</CardTitle>
                            </div>
                            <CardDescription>Irreversible account actions.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <p className="text-sm text-muted-foreground mb-4">
                                Deleting your account will remove all your data, reports, and settings permanently. This action cannot be undone.
                            </p>

                            <AlertDialog>
                                <AlertDialogTrigger asChild>
                                    <Button variant="destructive" className="w-full">
                                        <Trash2 className="mr-2 h-4 w-4" />
                                        Delete Account
                                    </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                    <AlertDialogHeader>
                                        <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                                        <AlertDialogDescription>
                                            This action cannot be undone. This will permanently delete your account and remove your data from our servers.
                                        </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                                        <AlertDialogAction onClick={handleDeleteAccount} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                                            Delete Account
                                        </AlertDialogAction>
                                    </AlertDialogFooter>
                                </AlertDialogContent>
                            </AlertDialog>
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}
