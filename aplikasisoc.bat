@echo off
title SOC Nexus Dashboard
cd /d C:\Users\usr\Documents\aplikasisoc
start http://localhost:8000/
python -m uvicorn app.main:app