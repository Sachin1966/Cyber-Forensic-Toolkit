# 🕵️ Cyber Forensic AI Toolkit

> **Advanced AI-powered platform for cyber threat detection, digital forensics, and automated MLOps.**

The **Cyber Forensic AI Toolkit** is a full-stack application designed to assist security analysts and forensic investigators. It leverages Machine Learning to detect phishing URLs, spam emails, malware files, and network anomalies in real-time. The system features a production-grade **MLOps Dashboard** for continuous model monitoring, retraining, and system health tracking.

---

## 🚀 Key Features

### 🔍 Forensic Analysis Tools
*   **URL Analyzer:** Detects phishing and malicious URLs using a Random Forest model trained on lexical features.
*   **Email Analyzer:** Classifies emails as Spam or Ham using TF-IDF vectorization and content analysis.
*   **File Analyzer:** Scans uploaded files (PE headers, static analysis) to detect malware signatures.
*   **PCAP Analyzer:** processes `.pcap` files to identify suspicious network traffic and potential intrusions.

### 🧠 MLOps Dashboard
*   **Real-Time Monitoring:** View live CPU, RAM, and Disk usage of the server.
*   **Live Training:** Trigger model retraining from the UI with real-time log streaming.
*   **Model Registry:** Track model versions, file sizes, and performance metrics (Accuracy, Precision, Recall).
*   **Visualizations:** Interactive charts showing training performance history and metric comparisons.
*   **Pipeline Integrity:** Integrated **DVC** status checks to ensure data and pipelines are synchronized.

### 📊 Reporting & Alerts
*   **Automated Reports:** Generates PDF forensic reports for analyzed threats.
*   **Email Alerts:** Sends immediate notifications for high-risk findings.
*   **User Management:** Secure JWT-based authentication and user role management.

---

## 🛠️ Tech Stack

### Frontend
*   **Framework:** [React](https://react.dev/) (Vite)
*   **Language:** TypeScript
*   **Styling:** Tailwind CSS, Shadcn UI
*   **Visualization:** Recharts
*   **Icons:** Lucide React

### Backend & AI
*   **Server:** Python (Flask)
*   **ML Frameworks:** Scikit-learn, Pandas, NumPy
*   **MLOps:** [MLflow](https://mlflow.org/) (Tracking), [DVC](https://dvc.org/) (Data Versioning)
*   **System Monitoring:** Psutil

### DevOps
*   **Containerization:** Docker
*   **CI/CD:** GitHub Actions
*   **Database:** SQLite

---

## 📂 Project Structure

```bash
NLP/
├── dataset/                  # Raw training datasets (CSV, PCAP)
├── dvc.yaml                  # DVC pipeline stages
├── ml_pipeline.py            # Main ML training & logging script
├── train_dynamic.py          # Alternative training script
├── deploy_frontend.py        # Script to deploy React build to Flask
├── logs/                     # Training logs
├── mlruns/                   # MLflow tracking data
├── .github/workflows/        # CI/CD definitions
│
├── forensic-ai-hub/
│   ├── backend/              # Flask Backend
│   │   ├── app.py            # API Entry Point
│   │   ├── mlops.py          # MLOps logic & routing
│   │   ├── predictions/      # ML Inference modules
│   │   ├── models/           # Serialized models (.pkl) & metrics.json
│   │   └── requirements.txt  # Python dependencies
│   │
│   └── src/                  # React Frontend
│       ├── components/       # UI Components (Charts, Layouts)
│       ├── pages/            # Page Views (Dashboard, MLOps, Analyzers)
│       └── lib/              # Utilities
```

---

## ⚡ Getting Started

### Prerequisites
*   Python 3.9+
*   Node.js & npm
*   Git

### 1. Installation

**Clone the repository:**
```bash
git clone https://github.com/your-repo/cyber-forensic-toolkit.git
cd cyber-forensic-toolkit
```

**Install Backend Dependencies:**
```bash
pip install -r forensic-ai-hub/backend/requirements.txt
pip install mlflow dvc psutil
```

**Install Frontend Dependencies:**
```bash
cd forensic-ai-hub
npm install
cd ..
```

### 2. MLOps Setup (DVC & MLflow)

**Initialize DVC (if not already done):**
```bash
dvc init
# Ensure dataset folders are tracked if using remote storage
# dvc pull 
```

**Verify Pipeline:**
```bash
dvc status
```

### 3. Running the Application

**Option A: Full Stack (Recommended for Dev)**

1.  **Start Backend:**
    ```bash
    cd forensic-ai-hub/backend
    python app.py
    ```
    *Server runs on http://localhost:5000*

2.  **Start Frontend (in a new terminal):**
    ```bash
    cd forensic-ai-hub
    npm run dev
    ```
    *App runs on http://localhost:5173*

**Option B: Production Build**

1.  **Build Frontend:**
    ```bash
    cd forensic-ai-hub
    npm run build
    ```
2.  **Deploy to Backend:**
    ```bash
    python deploy_frontend.py
    ```
3.  **Run Backend:**
    ```bash
    python forensic-ai-hub/backend/app.py
    ```
    *Access the app at http://localhost:5000*

---

## 🎮 Usage Guide

### MLOps Dashboard
Navigate to the **MLOps** tab in the sidebar.
*   **System Health:** Check if "MLflow", "Backend", and "DVC" are Green/Active.
*   **Retraining:** Click **"Start Retraining"** to launch the pipeline. Go to the "Training & Logs" tab to watch the real-time progress.
*   **Registry:** Click "Details" on any model to view its specific accuracy metrics and file info.

### Running Analysis
1.  Select an analyzer (e.g., **URL Analyzer**).
2.  Input the target (URL, Email text, or upload a File).
3.  Click "Analyze".
4.  View the **Threat Score**, classification, and a detailed breakdown of features.
5.  High-risk findings will automatically trigger an email alert if configured.

---

## 🤝 Contributing

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/NewAnalyzer`).
3.  Commit your changes (`git commit -m 'Add new analyzer'`).
4.  Push to the branch (`git push origin feature/NewAnalyzer`).
5.  Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
