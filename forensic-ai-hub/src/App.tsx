import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Layout } from "@/components/layout/Layout";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import Index from "./pages/Index";
import URLAnalyzer from "./pages/URLAnalyzer";
import EmailAnalyzer from "./pages/EmailAnalyzer";
import FileAnalyzer from "./pages/FileAnalyzer";
import PCAPAnalyzer from "./pages/PCAPAnalyzer";
import Reports from "./pages/Reports";
import ReportDetails from "./pages/ReportDetails";
import Training from "./pages/Training";
import MLOps from "./pages/MLOps";
import NotFound from "./pages/NotFound";
import Login from "./pages/Login";
import Settings from "./pages/Settings";

const queryClient = new QueryClient();

// Protected Route Component
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center">Loading...</div>;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

const AppRoutes = () => {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      {/* Protected Routes */}
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Index />} />
                <Route path="/url-analyzer" element={<URLAnalyzer />} />
                <Route path="/email-analyzer" element={<EmailAnalyzer />} />
                <Route path="/file-analyzer" element={<FileAnalyzer />} />
                <Route path="/pcap-analyzer" element={<PCAPAnalyzer />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/reports/:id" element={<ReportDetails />} />
                <Route path="/training" element={<Training />} />
                <Route path="/mlops" element={<MLOps />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  );
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <AuthProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </AuthProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
