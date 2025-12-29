import { useLocation, Link } from "react-router-dom";
import { useEffect } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Shield, Home, AlertTriangle } from "lucide-react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh]">
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5 }}
        className="text-center"
      >
        <div className="relative mb-8">
          <motion.div
            animate={{
              boxShadow: [
                "0 0 20px hsl(var(--destructive) / 0.3)",
                "0 0 40px hsl(var(--destructive) / 0.5)",
                "0 0 20px hsl(var(--destructive) / 0.3)",
              ],
            }}
            transition={{ duration: 2, repeat: Infinity }}
            className="w-24 h-24 rounded-full bg-destructive/10 flex items-center justify-center mx-auto"
          >
            <AlertTriangle className="w-12 h-12 text-destructive" />
          </motion.div>
        </div>

        <h1 className="text-7xl font-display font-bold text-foreground mb-4">
          <span className="text-destructive">4</span>
          <span className="text-primary">0</span>
          <span className="text-destructive">4</span>
        </h1>

        <p className="text-xl text-muted-foreground mb-2">
          Access Denied
        </p>
        <p className="text-sm text-muted-foreground mb-8 max-w-md mx-auto">
          The requested resource <code className="text-primary">{location.pathname}</code> could not be found in the system.
        </p>

        <div className="flex items-center justify-center gap-4">
          <Button variant="cyber" asChild>
            <Link to="/">
              <Home className="w-4 h-4 mr-2" />
              Return to Dashboard
            </Link>
          </Button>
          <Button variant="outline" asChild>
            <Link to="/reports">
              <Shield className="w-4 h-4 mr-2" />
              View Reports
            </Link>
          </Button>
        </div>
      </motion.div>
    </div>
  );
};

export default NotFound;
