@echo off
chcp 65001 > nul
echo ======================================================================
echo   Comunication_LTD - Push Project to GitHub
echo ======================================================================
echo.
set /p REPO_URL="Enter your GitHub Repository URL (e.g., https://github.com/username/repo.git): "

if "%REPO_URL%"=="" (
    echo [!] No URL provided. Aborting.
    pause
    exit /b 1
)

echo.
echo [*] Setting remote origin...
git remote remove origin 2>nul
git remote add origin %REPO_URL%

echo [*] Pushing branch main to GitHub...
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Successfully uploaded all code to GitHub!
) else (
    echo.
    echo [-] Push failed. Make sure you have write permissions to the repository.
)

pause
