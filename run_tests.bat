@echo off
chcp 65001 > nul
echo ======================================================================
echo   Running Automated Cyber Security Verification Suite
echo ======================================================================
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" tests\run_all_tests.py
pause
