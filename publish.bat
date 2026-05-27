@echo off
setlocal

set "PROJECT=src\ApimPolicyCompiler.Cli\ApimPolicyCompiler.Cli.csproj"
set "FRAMEWORK=net10.0"
set "CONFIGURATION=Release"
set "RID=win-x64"
set "EXECUTABLE_NAME=apim-policy-compiler.exe"

dotnet publish "%PROJECT%" ^
  -c "%CONFIGURATION%" ^
  -r "%RID%" ^
  -p:PublishAot=true ^
  -v minimal ^
  -nr:false

if errorlevel 1 exit /b %errorlevel%

set "BINARY_PATH=src\ApimPolicyCompiler.Cli\bin\%CONFIGURATION%\%FRAMEWORK%\%RID%\publish\%EXECUTABLE_NAME%"

echo.
echo Published binary:
echo %BINARY_PATH%
