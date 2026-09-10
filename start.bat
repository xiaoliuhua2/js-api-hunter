@echo off
setlocal

rem 优先用项目自带的 .venv（已含 fastapi / uvicorn / httpx / playwright）
set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=C:\Users\86182\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

set "PORT=8765"
set "URL=http://127.0.0.1:%PORT%"

echo.
echo   JS API Hunter  ^|  JS 接口提取工具
echo   ------------------------------------
echo   服务地址: %URL%
echo   关闭本窗口即停止服务
echo.

cd /d "%~dp0"

rem ------------------------------------------------------------------
rem  等服务真的监听端口之后再打开浏览器。
rem
rem  服务加载 fastapi / uvicorn 需要 1.5~2 秒才能监听端口。原来是无条件
rem  start 浏览器，浏览器毫秒级就跳过去了，那时端口还空着，页面就停在
rem  「无法访问此网站」—— 这才是「双击后打不开」的原因。
rem
rem  这里让一个后台进程轮询端口，通了再开浏览器；最多等 40 次
rem  （约 30 秒）后放弃，此时服务窗口里会有报错可看。
rem ------------------------------------------------------------------
start "" /b powershell -NoProfile -ExecutionPolicy Bypass -Command "$u='%URL%'; $p=%PORT%; for($i=0;$i -lt 40;$i++){ if(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue){ Start-Process $u; break }; Start-Sleep -Milliseconds 300 }"

"%PY%" server.py

pause
