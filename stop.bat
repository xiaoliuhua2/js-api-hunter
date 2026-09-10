@echo off
setlocal enabledelayedexpansion

rem ==================================================================
rem  JS API Hunter - stop server
rem
rem  Usage:
rem    double-click             stop the service on port 8765
rem    stop.bat 9000            stop the service on port 9000
rem
rem  适用于没有窗口可以按 Ctrl+C 的情况（后台运行、窗口被关掉、
rem  进程成了孤儿）。这里按「谁在监听这个端口」找 PID 再结束，
rem  不依赖任何控制台窗口。
rem ==================================================================

set "PORT=8765"
if not "%~1"=="" set "PORT=%~1"

echo.
echo   JS API Hunter ^| 停止服务（端口 %PORT%）
echo   ------------------------------------
echo.

set "KILLED=0"
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /i /c:"LISTENING" ^| findstr /c:":%PORT% "') do (
    taskkill /F /PID %%P >nul 2>&1
    if not errorlevel 1 (
        echo   [OK] 已结束进程  PID=%%P
        set "KILLED=1"
    )
)

if "!KILLED!"=="0" echo   [i] 没有进程在监听 %PORT%，服务应该本来就没在跑。

echo.
rem 设置 JAH_NOPAUSE=1 可跳过等待按键（方便被别的脚本调用）
if not defined JAH_NOPAUSE pause
