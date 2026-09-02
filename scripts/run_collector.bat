@echo off

cd /d "%~dp0\.."

if not exist "logs" mkdir "logs"

".venv\Scripts\python.exe" "src\collector.py" --continuous >> "logs\collector.log" 2>&1