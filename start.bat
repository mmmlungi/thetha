@echo off
rem Double-click to start Thetha with demo data, then open the browser.
cd /d "%~dp0"
python run.py --seed
pause
