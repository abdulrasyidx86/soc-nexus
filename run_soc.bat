@echo off
title SOC Analysis Console
cd /d C:\Users\usr\Documents\aplikasisoc
start http://localhost:8000/docs
python -m uvicorn app.main:app