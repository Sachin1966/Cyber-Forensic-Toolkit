import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { GoogleLogin, CredentialResponse } from "@react-oauth/google";
import { jwtDecode } from "jwt-decode";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";
import { ShieldCheck, Lock, Mail, User, Key } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const Login = () => {
    const { login, user } = useAuth();
    const navigate = useNavigate();
    const [isRegistering, setIsRegistering] = useState(false);
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [name, setName] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        console.log("Login: checking user state", user);
        if (user) {
            console.log("Login: user found, redirecting to /");
            navigate("/", { replace: true });
        }
    }, [user, navigate]);

    const handleGoogleSuccess = async (credentialResponse: CredentialResponse) => {
        if (credentialResponse.credential) {
            try {
                const decoded: any = jwtDecode(credentialResponse.credential);

                const response = await fetch('/api/auth/google', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: credentialResponse.credential }),
                    credentials: 'include'
                });

                if (response.ok) {
                    const data = await response.json();
                    if (!data.access_token) {
                        toast.error("Login successful but no token received");
                        console.error("Login: Missing access_token in response", data);
                        return;
                    }
                    console.log("Login: Google Auth Success. Token:", data.access_token.substring(0, 10) + "...");
                    login(data);
                    toast.success(`Welcome back, ${data.user.name}!`);
                } else {
                    console.error("Backend auth failed");
                    toast.error("Google Authentication failed on server");
                    // REMOVED UNSAFE FALLBACK: Do not login without backend verification
                }
            } catch (error) {
                console.error("Login Failed", error);
                toast.error("Login Failed");
            }
        }
    };

    const handleEmailAuth = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);

        const endpoint = isRegistering ? '/api/auth/register' : '/api/auth/login';
        const body = isRegistering
            ? { email, password, name }
            : { email, password };

        try {
            const response = await fetch(`${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                credentials: 'include'
            });

            const data = await response.json();

            if (response.ok) {
                console.log("Login: Email Auth Success", data);
                if (!data.access_token) {
                    console.error("Login: Missing access_token in response");
                    toast.error("Server returned valid response but missing token");
                    return;
                }
                console.log("Login: Calling context.login() with token:", data.access_token.substring(0, 10) + "...");
                login(data);
                toast.success(isRegistering ? "Account created successfully!" : `Welcome back, ${data.user.name}!`);
                // Navigation is handled by the useEffect hook when user state updates
            } else {
                toast.error(data.error || "Authentication failed");
            }
        } catch (error) {
            console.error("Auth Error", error);
            toast.error("Something went wrong. Please try again.");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen w-full flex items-center justify-center bg-background relative overflow-hidden">
            {/* Background Effects */}
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-primary/10 via-background to-background z-0"></div>
            <div className="absolute top-0 left-0 w-full h-full bg-[url('/grid.svg')] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))] opacity-20 z-0"></div>

            <div className="relative z-10 w-full max-w-md p-8">
                <div className="bg-card/50 backdrop-blur-xl border border-border rounded-2xl p-8 shadow-2xl flex flex-col items-center space-y-6 animate-fade-in">

                    {/* Logo / Icon */}
                    <div className="w-16 h-16 rounded-full bg-primary/20 flex items-center justify-center mb-2 ring-2 ring-primary/50 ring-offset-2 ring-offset-background">
                        <ShieldCheck className="w-8 h-8 text-primary" />
                    </div>

                    {/* Title */}
                    <div className="space-y-2 text-center">
                        <h1 className="text-3xl font-bold tracking-tighter bg-clip-text text-transparent bg-gradient-to-r from-white to-white/60">
                            Forensic AI Hub
                        </h1>
                        <p className="text-muted-foreground text-sm">
                            {isRegistering ? "Create your secure account" : "Secure Access for Authorized Personnel Only"}
                        </p>
                    </div>

                    {/* Email Auth Form */}
                    <form onSubmit={handleEmailAuth} className="w-full space-y-4">
                        {isRegistering && (
                            <div className="space-y-2">
                                <Label htmlFor="name">Full Name</Label>
                                <div className="relative">
                                    <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                    <Input
                                        id="name"
                                        placeholder="John Doe"
                                        className="pl-10 bg-background/50"
                                        value={name}
                                        onChange={(e) => setName(e.target.value)}
                                        required
                                    />
                                </div>
                            </div>
                        )}

                        <div className="space-y-2">
                            <Label htmlFor="email">Email Address</Label>
                            <div className="relative">
                                <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="name@example.com"
                                    className="pl-10 bg-background/50"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="password">Password</Label>
                            <div className="relative">
                                <Key className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                <Input
                                    id="password"
                                    type="password"
                                    placeholder="••••••••"
                                    className="pl-10 bg-background/50"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    required
                                />
                            </div>
                        </div>

                        <Button type="submit" className="w-full" disabled={isLoading}>
                            {isLoading ? "Processing..." : (isRegistering ? "Create Account" : "Sign In")}
                        </Button>
                    </form>

                    {/* Divider */}
                    <div className="relative w-full">
                        <div className="absolute inset-0 flex items-center">
                            <span className="w-full border-t border-border/50" />
                        </div>
                        <div className="relative flex justify-center text-xs uppercase">
                            <span className="bg-background px-2 text-muted-foreground">Or continue with</span>
                        </div>
                    </div>

                    {/* Google Login Button */}
                    <div className="w-full flex justify-center">
                        <GoogleLogin
                            onSuccess={handleGoogleSuccess}
                            onError={() => {
                                console.log('Login Failed');
                                toast.error("Login Failed");
                            }}
                            theme="filled_black"
                            shape="pill"
                            size="large"
                            width="300"
                            text="continue_with"
                        />
                    </div>

                    {/* Toggle Login/Register */}
                    <div className="text-center text-sm">
                        <span className="text-muted-foreground">
                            {isRegistering ? "Already have an account? " : "Don't have an account? "}
                        </span>
                        <button
                            onClick={() => setIsRegistering(!isRegistering)}
                            className="text-primary hover:underline font-medium"
                        >
                            {isRegistering ? "Sign In" : "Sign Up"}
                        </button>
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground/60">
                        <Lock className="w-3 h-3" />
                        <span>End-to-end encrypted connection</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Login;
