@echo off
chcp 65001 > nul
echo ======================================================================
echo   Comunication_LTD - Secure Version (Port 5002)
echo   Cyber Security Final Project
echo ======================================================================
echo.
echo Initializing secure database...
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" secure_version\database\init_db.py
echo.
echo Starting secure web server on http://127.0.0.1:5002 ...
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" secure_version\app.py
pause
