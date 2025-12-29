import { useCallback, useState } from "react";
import { cn } from "@/lib/utils";
import { Upload, File, X, AlertCircle } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface FileDropzoneProps {
  onFileSelect: (file: File) => void;
  accept?: string;
  maxSize?: number; // in MB
  className?: string;
}

export function FileDropzone({
  onFileSelect,
  accept = "*",
  maxSize = 50,
  className,
}: FileDropzoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDragIn = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragOut = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const validateFile = (file: File): boolean => {
    setError(null);
    
    if (file.size > maxSize * 1024 * 1024) {
      setError(`File size must be less than ${maxSize}MB`);
      return false;
    }

    return true;
  };

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);

      const file = e.dataTransfer.files[0];
      if (file && validateFile(file)) {
        setSelectedFile(file);
        onFileSelect(file);
      }
    },
    [onFileSelect, maxSize]
  );

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && validateFile(file)) {
      setSelectedFile(file);
      onFileSelect(file);
    }
  };

  const clearFile = () => {
    setSelectedFile(null);
    setError(null);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  };

  return (
    <div className={cn("w-full", className)}>
      <div
        onDragEnter={handleDragIn}
        onDragLeave={handleDragOut}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={cn(
          "relative border-2 border-dashed rounded-xl p-8 transition-all duration-300 cursor-pointer",
          isDragging
            ? "border-primary bg-primary/10 scale-[1.02]"
            : "border-border hover:border-primary/50 hover:bg-muted/30",
          selectedFile && "border-success bg-success/5"
        )}
      >
        <input
          type="file"
          accept={accept}
          onChange={handleFileInput}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />

        <AnimatePresence mode="wait">
          {selectedFile ? (
            <motion.div
              key="file"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex items-center justify-center gap-4"
            >
              <div className="w-12 h-12 rounded-lg bg-success/10 flex items-center justify-center">
                <File className="w-6 h-6 text-success" />
              </div>
              <div className="flex flex-col">
                <span className="font-medium text-foreground">{selectedFile.name}</span>
                <span className="text-sm text-muted-foreground">
                  {formatFileSize(selectedFile.size)}
                </span>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  clearFile();
                }}
                className="p-2 rounded-lg hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </motion.div>
          ) : (
            <motion.div
              key="upload"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex flex-col items-center gap-4"
            >
              <div
                className={cn(
                  "w-16 h-16 rounded-xl flex items-center justify-center transition-all duration-300",
                  isDragging
                    ? "bg-primary/20 text-primary scale-110"
                    : "bg-muted text-muted-foreground"
                )}
              >
                <Upload className="w-8 h-8" />
              </div>
              <div className="text-center">
                <p className="font-medium text-foreground">
                  {isDragging ? "Drop file here" : "Drag & drop file here"}
                </p>
                <p className="text-sm text-muted-foreground mt-1">
                  or click to browse • Max {maxSize}MB
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="mt-3 flex items-center gap-2 text-destructive"
          >
            <AlertCircle className="w-4 h-4" />
            <span className="text-sm">{error}</span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
