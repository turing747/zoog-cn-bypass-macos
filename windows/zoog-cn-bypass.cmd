@echo off
rem Launcher for ZoogCNBypass (Windows). Uses a bundled exe if present, otherwise Python 3.
setlocal
set "PKG=%~dp0zoog_cn_bypass"
if exist "%~dp0zoog-cn-bypass.exe" (
  "%~dp0zoog-cn-bypass.exe" %*
  exit /b %errorlevel%
)
where python >nul 2>nul || goto usepy
python "%PKG%" %*
exit /b %errorlevel%
:usepy
py -3 "%PKG%" %*
exit /b %errorlevel%
