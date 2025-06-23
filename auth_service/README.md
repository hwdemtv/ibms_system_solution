# IBMS认证与管理服务

这是IBMS智能建筑管理系统的认证与管理服务，提供用户认证、权限管理和系统配置功能。

## 功能特性

- 用户注册和登录
- JWT令牌认证
- 用户权限管理
- 管理员功能
- 外部服务代理

## 安装和运行

1. 创建虚拟环境：
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 运行服务：
```bash
python src/main.py
```

服务将在 http://localhost:5000 启动

## API接口

### 用户认证
- POST /api/register - 用户注册
- POST /api/login - 用户登录
- GET /api/verify - 令牌验证
- GET /api/profile - 获取用户资料
- PUT /api/profile - 更新用户资料

### 管理员功能
- GET /api/admin/users - 获取所有用户
- PUT /api/admin/users/<id> - 更新用户信息
- DELETE /api/admin/users/<id> - 删除用户
- POST /api/admin/users/<id>/reset-password - 重置用户密码

### 代理服务
- POST /api/proxy/blinko-login - Blinko自动登录
- GET /api/proxy/blinko-proxy/<path> - Blinko内容代理

## 默认账户

- 用户名：admin
- 密码：admin123 