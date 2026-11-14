@echo off
chcp 65001 >nul
title DannoIDS - Web Attack Detection System
cls
echo ================================================================
echo           DannoIDS - ML WEB ATTACK DETECTION SYSTEM
echo ================================================================
echo.
echo  [1] Khoi dong Web Dashboard (http://localhost:5000)
echo  [2] Quet kiem tra file log mau (logsfile.txt - 20 requests)
echo  [3] Quet file Nginx/Apache access log (access.log)
echo  [4] Cai dat thu vien can thiet (pip install -r requirements.txt)
echo  [5] Thoat
echo.
set /p choice="Nhap lua chon [1-5]: "

if "%choice%"=="1" (
    echo.
    echo [*] Dang khoi dong Web Dashboard...
    echo [*] Truy cap tren trinh duyet: http://localhost:5000
    echo [*] Nhan Ctrl+C de dung server.
    echo.
    python web_app.py
) else if "%choice%"=="2" (
    echo.
    echo [*] Dang phan tich logsfile.txt...
    python detector.py --log logsfile.txt
    echo.
    pause
) else if "%choice%"=="3" (
    echo.
    echo [*] Dang phan tich access.log...
    python detector.py --log access.log
    echo.
    pause
) else if "%choice%"=="4" (
    echo.
    echo [*] Dang cai dat thu vien...
    pip install -r requirements.txt
    echo.
    pause
) else (
    exit /b 0
)

