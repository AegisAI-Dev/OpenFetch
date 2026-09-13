@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
if exist "..\.venv\Scripts\python.exe" set "PYTHON=..\.venv\Scripts\python.exe"

set "PYTHONPATH=%CD%\src"
"%PYTHON%" -m PyInstaller OpenFetch.spec --clean --noconfirm
