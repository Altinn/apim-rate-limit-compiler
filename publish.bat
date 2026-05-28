@echo off
setlocal

set "PROJECT=src\ApimRateLimitCompiler.Cli\ApimRateLimitCompiler.Cli.csproj"
set "FRAMEWORK=net10.0"
set "CONFIGURATION=Release"
set "RID=win-x64"
set "EXECUTABLE_NAME=apim-rate-limit-compiler.exe"
set "REQUESTED_VERSION=%~1"

if "%REQUESTED_VERSION%"=="" set "REQUESTED_VERSION=%PUBLISH_VERSION%"
set "PUBLISH_VERSION=%REQUESTED_VERSION%"
if /i "%PUBLISH_VERSION:~0,1%"=="v" set "PUBLISH_VERSION=%PUBLISH_VERSION:~1%"

set "VERSION_ARGS="
if not "%PUBLISH_VERSION%"=="" (
  echo %PUBLISH_VERSION%| findstr /r "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*[-.0-9A-Za-z]*$" >nul
  if errorlevel 1 (
    echo Version must be SemVer-like, for example v1.2.3 or 1.2.3-preview.1. 1>&2
    exit /b 2
  )
  set "VERSION_ARGS=-p:Version=%PUBLISH_VERSION% -p:InformationalVersion=%PUBLISH_VERSION%+local"
)

dotnet publish "%PROJECT%" ^
  -c "%CONFIGURATION%" ^
  -r "%RID%" ^
  -p:PublishAot=true ^
  %VERSION_ARGS% ^
  -v minimal ^
  -nr:false

if errorlevel 1 exit /b %errorlevel%

set "BINARY_PATH=src\ApimRateLimitCompiler.Cli\bin\%CONFIGURATION%\%FRAMEWORK%\%RID%\publish\%EXECUTABLE_NAME%"

echo.
echo Published binary:
echo %BINARY_PATH%
if not "%PUBLISH_VERSION%"=="" echo Version: %PUBLISH_VERSION%
