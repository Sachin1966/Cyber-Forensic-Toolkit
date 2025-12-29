@echo off
echo Starting Forensic AI Hub...

:: Start Backend
start "Forensic AI Hub Backend" cmd /k "cd backend && python -m pip install -r requirements.txt && python app.py"

:: Start Frontend
start "Forensic AI Hub Frontend" cmd /k "npm install && npm run dev"

echo Both servers are starting...
echo Backend: http://localhost:5000
echo Frontend: http://localhost:8080 (or check console)
pause
