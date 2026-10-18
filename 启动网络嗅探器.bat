@echo off
chcp 65001 >nul
echo Starting Network Sniffer...
echo.

powershell -Command "Start-Process python -ArgumentList 'sniffer_gui.py' -Verb RunAs -WorkingDirectory '%~dp0'"

echo Started! Please check the popup window.
echo.
pause
