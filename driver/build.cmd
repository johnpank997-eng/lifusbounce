@echo off
setlocal
cd /d "%~dp0"
set "DRIVER_PATH=%~dp0..\bin\driver\lifus.sys"
if /i "%~1"=="--load-only" goto load_driver
for /f "delims=" %%i in ('where /r "%ProgramW6432%\Microsoft Visual Studio" vcvars64.bat 2^>nul') do if not defined VCVARS set "VCVARS=%%i"
for /f "delims=" %%i in ('where /r "%ProgramFiles%\Microsoft Visual Studio" vcvars64.bat 2^>nul') do if not defined VCVARS set "VCVARS=%%i"
for /f "delims=" %%i in ('where /r "%ProgramFiles(x86)%\Microsoft Visual Studio" vcvars64.bat 2^>nul') do if not defined VCVARS set "VCVARS=%%i"
for /f "delims=" %%i in ('dir /b /ad "%ProgramFiles(x86)%\Windows Kits\10\Include\10.*" 2^>nul ^| sort /r') do if not defined WDK_VERSION set "WDK_VERSION=%%i"
set "WDK_INCLUDE=%ProgramFiles(x86)%\Windows Kits\10\Include\%WDK_VERSION%"
set "WDK_LIB=%ProgramFiles(x86)%\Windows Kits\10\Lib\%WDK_VERSION%"
if not exist "%VCVARS%" goto missing_vcvars
if not exist "%WDK_INCLUDE%\km" goto missing_wdk
call "%VCVARS%" >nul
if errorlevel 1 goto build_failed
sc.exe stop lifus >nul 2>&1
sc.exe delete lifus >nul 2>&1
"..\bin\loader\loader.exe" unload lifus >nul 2>&1
sc.exe query lifus 2>nul | findstr /C:"RUNNING" >nul
if not errorlevel 1 (
    echo [driver] reboot required
    goto finish_failed
)
if not exist "..\build\driver" mkdir "..\build\driver"
if not exist "..\bin\driver" mkdir "..\bin\driver"
echo [driver] build
echo [driver] compile
cl /nologo /c /kernel /D_AMD64_ /D_WIN32 /D_WIN64 /DNTDDI_VERSION=0x0A000000 /W3 /Fo"..\build\driver\lifus.obj" /I "include" /I "%WDK_INCLUDE%\km" "src\lifus.c"
if errorlevel 1 goto build_failed
echo [driver] resource
rc /fo "..\build\driver\lifus.res" "resources\lifus.rc"
if errorlevel 1 goto build_failed
echo [driver] link
link /nologo /driver:wdm /entry:DriverEntry /subsystem:native /incremental:no /opt:ref /opt:icf /nodefaultlib /merge:_TEXT=.text /merge:_PAGE=PAGE /merge:_RDATA=.rdata /out:"..\bin\driver\lifus.sys" "..\build\driver\lifus.obj" "..\build\driver\lifus.res" "%WDK_LIB%\km\x64\ntoskrnl.lib" "%WDK_LIB%\km\x64\hal.lib" "%WDK_LIB%\km\x64\wdmsec.lib" "%WDK_LIB%\km\x64\libcntpr.lib" "%WDK_LIB%\km\x64\bufferoverflowfastfailk.lib"
if errorlevel 1 goto build_failed
powershell.exe -NoProfile -Command "Write-Host '[driver] built' -ForegroundColor Green"
echo [loader] build
if not exist "..\build\loader" mkdir "..\build\loader"
if not exist "..\bin\loader" mkdir "..\bin\loader"
cl /nologo /c /O2 /W3 /Fo"..\build\loader\loader.obj" /I "loader" "loader\loader.c"
if errorlevel 1 goto build_failed
link /nologo /subsystem:console /entry:wmainCRTStartup /incremental:no /opt:ref /opt:icf /out:"..\bin\loader\loader.exe" "..\build\loader\loader.obj" kernel32.lib advapi32.lib dbghelp.lib winhttp.lib
if errorlevel 1 goto build_failed
powershell.exe -NoProfile -Command "Write-Host '[loader] built' -ForegroundColor Green"
if /i not "%~1"=="--no-pause" goto load_driver
:show_status
sc.exe query lifus 2^>nul | findstr /C:"RUNNING" >nul
if errorlevel 1 (
    echo [driver] not loaded
) else (
    powershell.exe -NoProfile -Command "Write-Host '[driver] loaded' -ForegroundColor Green"
)
exit /b 0
:load_driver
if not exist "%DRIVER_PATH%" goto driver_missing
if not exist "..\bin\loader\loader.exe" goto loader_missing
fltmc >nul 2>&1
if errorlevel 1 goto request_admin
if not exist "..\build\driver" mkdir "..\build\driver"
echo [driver] load
"..\bin\loader\loader.exe" load "%DRIVER_PATH%" >"..\build\driver\load.log" 2>&1
if errorlevel 1 goto load_failed
sc.exe query lifus 2^>nul | findstr /C:"RUNNING" >nul
if errorlevel 1 goto load_failed
powershell.exe -NoProfile -Command "Write-Host '[driver] loaded' -ForegroundColor Green"
goto finish
:request_admin
echo [admin] request
powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '--load-only' -Verb RunAs -Wait"
if errorlevel 1 goto load_failed
exit /b 0
:load_failed
if exist "..\build\driver\load.log" type "..\build\driver\load.log"
sc.exe delete lifus >nul 2>&1
echo [driver] load failed
goto finish_failed
:driver_missing
echo [driver] missing
goto finish_failed
:loader_missing
echo [loader] missing
goto finish_failed
:missing_vcvars
echo [vs] missing
goto finish_failed
:missing_wdk
echo [wdk] missing
goto finish_failed
:build_failed
echo [driver] build failed
goto finish_failed
:finish
if /i "%~1"=="--no-pause" exit /b 0
echo press a key
pause >nul
exit /b 0
:finish_failed
if /i "%~1"=="--no-pause" exit /b 1
echo press a key
pause >nul
exit /b 1
