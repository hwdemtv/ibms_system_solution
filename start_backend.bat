@echo off
echo 启动IBMS认证服务...
cd auth_service
if not exist venv (
    echo 创建虚拟环境...
    python -m venv venv
)
echo 激活虚拟环境...
call venv\Scripts\activate
echo 安装依赖...
pip install -r requirements.txt
echo 启动服务...
python src\main.py
pause 