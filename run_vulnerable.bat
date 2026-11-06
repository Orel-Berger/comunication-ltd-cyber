@echo off
chcp 65001 > nul
echo ======================================================================
echo   Comunication_LTD - Vulnerable Version (Port 5001)
echo   Cyber Security Final Project
echo ======================================================================
echo.
echo Initializing database...
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" vulnerable_version\database\init_db.py
echo.
echo Starting web server on http://127.0.0.1:5001 ...
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" vulnerable_version\app.py
pause
