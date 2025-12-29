import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { googleLogout } from '@react-oauth/google';
import { jwtDecode } from "jwt-decode";
import { SessionTimeoutModal } from '@/components/layout/SessionTimeoutModal';

interface UserProfile {
    email: string;
    name: string;
    picture: string;
    alert_preferences?: any;
    theme_preference?: string;
    show_badges?: number;
}

interface AuthContextType {
    user: UserProfile | null;
    login: (data: any) => void;
    logout: () => void;
    isLoading: boolean;
    extendSession: () => Promise<void>;
    updateUser: (userData: Partial<UserProfile>) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<UserProfile | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [showTimeoutModal, setShowTimeoutModal] = useState(false);

    const logout = useCallback(() => {
        console.log("UseAuth: Logging out");
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        googleLogout();
        setUser(null);
        setShowTimeoutModal(false);
    }, []);

    const login = (data: any) => {
        console.log("AuthContext: login called", data);
        if (!data.access_token) {
            console.error("AuthContext: No access_token provided in login data");
            return;
        }

        localStorage.setItem('access_token', data.access_token);
        if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);

        if (data.user) {
            localStorage.setItem('user', JSON.stringify(data.user));
            setUser(data.user);
        }
    };

    const updateUser = (userData: Partial<UserProfile>) => {
        if (!user) return;
        const updatedUser = { ...user, ...userData };
        setUser(updatedUser);
        localStorage.setItem('user', JSON.stringify(updatedUser));
    };

    const extendSession = async () => {
        try {
            const refreshToken = localStorage.getItem('refresh_token');
            if (!refreshToken) throw new Error("No refresh token");

            const response = await fetch('/api/auth/refresh', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${refreshToken}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('access_token', data.access_token);
                setShowTimeoutModal(false);
                console.log("Session extended");
            } else {
                console.error("Failed to refresh session");
                logout();
            }
        } catch (error) {
            console.error("Error extending session:", error);
            logout();
        }
    };

    // Check session on mount
    useEffect(() => {
        const initAuth = async () => {
            const token = localStorage.getItem('access_token');
            const storedUser = localStorage.getItem('user');

            if (token && storedUser) {
                try {
                    const decoded: any = jwtDecode(token);
                    const currentTime = Date.now() / 1000;

                    if (decoded.exp < currentTime) {
                        // Expired, try refresh
                        console.log("Token expired on load, trying refresh...");
                        await extendSession();
                    } else {
                        // Valid
                        setUser(JSON.parse(storedUser));
                    }
                } catch (e) {
                    console.error("Invalid token on load", e);
                    logout();
                }
            }
            setIsLoading(false);
        };
        initAuth();
    }, []);

    // Monitor Session
    useEffect(() => {
        if (!user) return;

        const interval = setInterval(() => {
            const token = localStorage.getItem('access_token');
            if (!token) return;

            try {
                const decoded: any = jwtDecode(token);
                const currentTime = Date.now() / 1000;
                const timeLeft = decoded.exp - currentTime;

                // If expired
                if (timeLeft <= 0) {
                    console.log("Session expired by timer");
                    logout();
                }
                // If < 5 mins (300 seconds) left, show modal
                else if (timeLeft < 300) {
                    if (!showTimeoutModal) setShowTimeoutModal(true);
                }
            } catch (e) {
                console.error("AuthContext: Token decode failed in monitor", e);
                logout();
            }
        }, 30000); // Check every 30s

        return () => clearInterval(interval);
    }, [user, logout, showTimeoutModal]);

    return (
        <AuthContext.Provider value={{ user, login, logout, isLoading, extendSession, updateUser }}>
            {children}
            <SessionTimeoutModal
                open={showTimeoutModal}
                onExtend={extendSession}
                onLogout={logout}
            />
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};
