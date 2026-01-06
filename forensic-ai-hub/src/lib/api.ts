// Real API layer connecting to Flask backend
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

// Types
export interface PredictionResult {
  prediction: string;
  confidence: number;
  threatScore: number;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface URLAnalysis {
  url: string;
  isPhishing: boolean;
  threatScore: number;
  features: {
    hasIP: boolean;
    urlLength: number;
    hasHTTPS: boolean;
    numDots: number;
    numDashes: number;
    hasAtSymbol: boolean;
    suspiciousKeywords: string[];
  };
  timestamp: string;
}

export interface EmailAnalysis {
  subject: string;
  isPhishing: boolean;
  isSpam: boolean;
  threatScore: number;
  suspiciousTerms: string[];
  senderReputation: 'trusted' | 'unknown' | 'suspicious';
  timestamp: string;
}

export interface FileAnalysis {
  filename: string;
  size: number;
  type: string;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
  isMalicious: boolean;
  threatScore: number;
  metadata: {
    entropy: number;
    sections: string[];
    imports: string[];
  };
  timestamp: string;
}

export interface PCAPAnalysis {
  filename: string;
  packetCount: number;
  protocols: Record<string, number>;
  anomalies: string[];
  threatScore: number;
  networkStats: {
    totalBytes: number;
    avgPacketSize: number;
    duration: number;
  };
  timestamp: string;
}

export interface DashboardStats {
  totalScans: number;
  maliciousDetected: number;
  urlsAnalyzed: number;
  emailsAnalyzed: number;
  filesAnalyzed: number;
  pcapsAnalyzed: number;
  recentActivity: ActivityItem[];
  threatTrend: ThreatTrendItem[];
}

export interface ActivityItem {
  id: string;
  type: 'url' | 'email' | 'file' | 'pcap';
  name: string;
  result: 'safe' | 'warning' | 'danger';
  threatScore: number;
  timestamp: string;
}

export interface ThreatTrendItem {
  date: string;
  safe: number;
  warning: number;
  danger: number;
}

export interface TrainingStatus {
  isTraining: boolean;
  progress: number;
  currentModel: string;
  modelsCompleted: string[];
  lastTrainedAt: string;
}

export interface ModelMetadata {
  name: string;
  accuracy: number;
  last_trained: string | null;
  status: string;
  description: string;
}

export interface DatasetStat {
  folder: string;
  desc: string;
  count: string;
}

// Helper for API calls
async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem('access_token');
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options?.headers,
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `API Error: ${response.statusText}`);
  }

  return response.json();
}

// API functions
export const api = {
  // URL Analysis
  async analyzeURL(url: string): Promise<URLAnalysis> {
    return fetchAPI<URLAnalysis>('/api/analyze/url', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  },

  // Email Analysis
  async analyzeEmail(emailContent: string, subject?: string): Promise<EmailAnalysis> {
    return fetchAPI<EmailAnalysis>('/api/analyze/email', {
      method: 'POST',
      body: JSON.stringify({ content: emailContent, subject }),
    });
  },

  // File Analysis
  async analyzeFile(file: File): Promise<FileAnalysis> {
    // Note: File upload usually requires FormData, not JSON
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('access_token');
    const headers: HeadersInit = token ? { 'Authorization': `Bearer ${token}` } : {};

    const response = await fetch(`${API_BASE_URL}/api/analyze/file`, {
      method: 'POST',
      body: formData,
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error('File analysis failed');
    }
    return response.json();
  },

  // PCAP Analysis
  async analyzePCAP(file: File): Promise<PCAPAnalysis> {
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('access_token');
    const headers: HeadersInit = token ? { 'Authorization': `Bearer ${token}` } : {};

    const response = await fetch(`${API_BASE_URL}/api/analyze/pcap`, {
      method: 'POST',
      body: formData,
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error('PCAP analysis failed');
    }
    return response.json();
  },

  // Dashboard Stats
  async getDashboardStats(): Promise<DashboardStats> {
    return fetchAPI<DashboardStats>('/api/stats');
  },

  // Training
  async startTraining(): Promise<{ success: boolean; message: string }> {
    return fetchAPI('/api/train/start', { method: 'POST' });
  },

  async getTrainingStatus(): Promise<TrainingStatus> {
    return fetchAPI<TrainingStatus>('/api/train/status');
  },

  async getModelStatus(): Promise<Record<string, ModelMetadata>> {
    return fetchAPI<Record<string, ModelMetadata>>('/api/model-status');
  },

  async getDatasetStats(): Promise<DatasetStat[]> {
    return fetchAPI<DatasetStat[]>('/api/dataset-stats');
  },

  // Models
  async reloadModels(): Promise<{ success: boolean; message: string }> {
    return fetchAPI('/api/models/reload', { method: 'POST' });
  },

  // Report Generation (PDF)
  async generateReport(analysisId: string): Promise<Blob> {
    const token = localStorage.getItem('access_token');
    const headers: HeadersInit = token ? { 'Authorization': `Bearer ${token}` } : {};

    const response = await fetch(`${API_BASE_URL}/api/reports/${analysisId}/pdf`, {
      headers,
      credentials: 'include',
    });
    if (!response.ok) throw new Error('Failed to generate report');
    return response.blob();
  },

  // Get Full Report Details
  async getReportDetails(analysisId: string): Promise<any> {
    return fetchAPI<any>(`/api/reports/${analysisId}`);
  },

  // Export All Reports
  async exportReports(): Promise<Blob> {
    const token = localStorage.getItem('access_token');
    const headers: HeadersInit = token ? { 'Authorization': `Bearer ${token}` } : {};

    const response = await fetch(`${API_BASE_URL}/api/reports/export`, {
      headers,
      credentials: 'include'
    });
    if (!response.ok) throw new Error('Failed to export reports');
    return response.blob();
  },

  // Get Reports
  async getReports(params?: { search?: string; type?: string; startDate?: string; endDate?: string }): Promise<ActivityItem[]> {
    const query = new URLSearchParams();
    if (params?.search) query.append('search', params.search);
    if (params?.type) query.append('type', params.type);
    if (params?.startDate) query.append('startDate', params.startDate);
    if (params?.endDate) query.append('endDate', params.endDate);

    return fetchAPI<ActivityItem[]>(`/api/reports?${query.toString()}`);
  },

  // User Settings
  async updateSettings(data: any): Promise<{ success: boolean; user: any }> {
    return fetchAPI<{ success: boolean; user: any }>('/api/user/settings', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async updatePassword(data: any): Promise<{ success: boolean; message: string }> {
    return fetchAPI<{ success: boolean; message: string }>('/api/user/password', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async deleteAccount(): Promise<{ success: boolean; message: string }> {
    return fetchAPI<{ success: boolean; message: string }>('/api/user/account', {
      method: 'DELETE',
    });
  },
};
