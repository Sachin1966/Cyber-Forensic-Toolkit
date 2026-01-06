import { useState, useEffect } from "react";
import { Bell, Search, Activity, LogOut, FileText, Check, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/context/AuthContext";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useNavigate, Link, useLocation } from "react-router-dom";
import { ScrollArea } from "@/components/ui/scroll-area";

interface NotificationItem {
  id: number;
  title: string;
  message: string;
  report_id: number;
  created_at: string;
  is_read: boolean;
}

export function Header() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);

  const API_BASE = import.meta.env.VITE_API_URL || "";

  const fetchNotifications = async () => {
    if (!user) return;
    try {
      const token = localStorage.getItem('access_token');
      if (!token) return;

      const res = await fetch(`${API_BASE}/api/notifications`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setNotifications(data);
        setUnreadCount(data.length);
      }
    } catch (error) {
      console.error("Failed to fetch notifications", error);
    }
  };

  // Poll every 30 seconds
  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 30000);
    return () => clearInterval(interval);
  }, [user]);

  const handleLogout = () => {
    logout();
    toast.info("Logged out successfully");
  };

  const handleNotificationClick = async (n: NotificationItem) => {
    try {
      const token = localStorage.getItem('access_token');
      await fetch(`${API_BASE}/api/notifications/${n.id}/read`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      // Remove from local state
      setNotifications(prev => prev.filter(item => item.id !== n.id));
      setUnreadCount(prev => Math.max(0, prev - 1));

      if (n.report_id) {
        navigate(`/reports/${n.report_id}`);
      }
    } catch (e) {
      console.error("Failed to mark read", e);
    }
  };

  return (
    <header className="h-16 border-b border-border bg-card/50 backdrop-blur-xl sticky top-0 z-40">
      <div className="h-full px-6 flex items-center justify-between">
        {/* Search */}
        {/* Search - Removed as per request */}
        <div className="flex items-center gap-4 flex-1 max-w-md"></div>

        {/* Navigation Links (Middle area mock) */}


        {/* Status & Actions */}
        <div className="flex items-center gap-4">
          {/* System Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-success/10 border border-success/30">
            <Activity className="w-4 h-4 text-success animate-pulse" />
            <span className="text-sm text-success font-medium">System Active</span>
          </div>

          {/* Notifications */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="relative">
                <Bell className="w-5 h-5" />
                {unreadCount > 0 && (
                  <Badge className="absolute -top-1 -right-1 w-5 h-5 p-0 flex items-center justify-center text-[10px]" variant="danger">
                    {unreadCount}
                  </Badge>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <DropdownMenuLabel>Notifications</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <ScrollArea className="h-[300px]">
                {notifications.length === 0 ? (
                  <div className="p-4 text-center text-sm text-muted-foreground">
                    No new notifications
                  </div>
                ) : (
                  notifications.map(n => (
                    <DropdownMenuItem key={n.id} className="p-3 cursor-pointer focus:bg-muted/50" onClick={() => handleNotificationClick(n)}>
                      <div className="flex gap-3 items-start">
                        <div className="mt-1">
                          <div className="w-2 h-2 rounded-full bg-destructive" />
                        </div>
                        <div className="space-y-1">
                          <p className="text-sm font-medium leading-none">{n.title}</p>
                          <p className="text-xs text-muted-foreground line-clamp-2">{n.message}</p>
                          <p className="text-[10px] text-muted-foreground/70">{new Date(n.created_at).toLocaleString()}</p>
                        </div>
                      </div>
                    </DropdownMenuItem>
                  ))
                )}
              </ScrollArea>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* User */}
          {user && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="relative h-8 w-8 rounded-full">
                  <Avatar className="h-8 w-8">
                    <AvatarImage src={user.picture} alt={user.name} />
                    <AvatarFallback>{user.name.charAt(0)}</AvatarFallback>
                  </Avatar>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-56" align="end" forceMount>
                <DropdownMenuLabel className="font-normal">
                  <div className="flex flex-col space-y-1">
                    <p className="text-sm font-medium leading-none">{user.name}</p>
                    <p className="text-xs leading-none text-muted-foreground">
                      {user.email}
                    </p>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => navigate('/settings')} className="cursor-pointer">
                  <Settings className="mr-2 h-4 w-4" />
                  <span>Settings</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleLogout} className="cursor-pointer text-destructive focus:text-destructive">
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>Log out</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
    </header>
  );
}
