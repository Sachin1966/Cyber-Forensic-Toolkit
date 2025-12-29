import React from "react";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "@/components/ui/alert-dialog";

interface SessionTimeoutModalProps {
    open: boolean;
    onExtend: () => void;
    onLogout: () => void;
}

export const SessionTimeoutModal: React.FC<SessionTimeoutModalProps> = ({
    open,
    onExtend,
    onLogout,
}) => {
    return (
        <AlertDialog open={open}>
            <AlertDialogContent>
                <AlertDialogHeader>
                    <AlertDialogTitle>Session Expiring Soon</AlertDialogTitle>
                    <AlertDialogDescription>
                        Your session is about to expire due to inactivity. Would you like to extend your session?
                    </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                    <AlertDialogCancel onClick={onLogout}>Logout</AlertDialogCancel>
                    <AlertDialogAction onClick={onExtend}>Extend Session</AlertDialogAction>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    );
};
