@echo off
title TV-EYE Console - by Mr_TV
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (
    python tveye.py %*
) else (
    echo [!] Python not found in PATH. Install Python 3.8+ from python.org
    pause
)
