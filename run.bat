@echo off
REM IDMF - one-click start on Windows (needs Python 3.10+ on PATH)
cd /d "%~dp0"
if not exist .venv (
  echo Creating virtual environment...
  python -m venv .venv || goto :err
  call .venv\Scripts\activate.bat
  python -m pip install --upgrade pip
  pip install -r requirements.txt || goto :err
) else (
  call .venv\Scripts\activate.bat
)
echo.
echo  IDMF is starting at http://127.0.0.1:8000
echo  Sign in with  investigator / forensics123  and click "Load demo case".
echo.
start "" http://127.0.0.1:8000
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
goto :eof
:err
echo Setup failed. Check that Python 3.10 or newer is installed and on PATH.
pause
