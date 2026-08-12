@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0airs-hooks.ps1" -Vendor cline -EventName TaskComplete %*
