#!/bin/bash
echo "启动IBMS前端应用..."
cd frontend
echo "启动HTTP服务器..."
python3 -m http.server 8080 