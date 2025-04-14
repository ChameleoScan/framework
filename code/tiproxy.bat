@echo off
set tidevice=.venv\Scripts\tidevice.exe

start /b "" %tidevice% relay 2200 22
start /b "" %tidevice% relay 6001 6000
start /b "" %tidevice% relay 8100 8100
start /b /wait "" %tidevice% relay 5000 5000

