@echo off
title Smart School ERP Launcher
echo ========================================================
echo Starting Smart School ERP (Backend + Frontend)
echo ========================================================
echo.
echo Launching Express Backend on port 5000...
start "School ERP Backend" cmd /k "cd /d %~dp0school-backend && npm start"

echo Launching React Frontend on port 3000...
start "School ERP Frontend" cmd /k "cd /d %~dp0school-frontend && npm run dev"

echo.
echo ========================================================
echo Both servers have been launched!
echo - Frontend:  http://localhost:3000
echo - Backend:   http://localhost:5000
echo - Health:    http://localhost:3000/api/health
echo ========================================================
pause
