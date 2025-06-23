# IBMS智能建筑管理系统

这是一个完整的智能建筑管理系统，集成了用户认证、系统设置、公共广播以及知识库等多个核心功能模块。

## 项目结构

```
ibms_system_solution/
├── auth_service/              # 后端认证服务
│   ├── src/
│   │   ├── models/           # 数据模型
│   │   │   └── user.py       # 用户模型定义
│   │   ├── routes/           # 路由处理
│   │   │   ├── user.py       # 用户相关API路由
│   │   │   ├── admin.py      # 管理员相关API路由
│   │   │   └── proxy.py      # 代理服务API路由
│   │   ├── utils/            # 工具函数
│   │   │   └── decorators.py # 权限控制装饰器
│   │   ├── static/           # 静态文件
│   │   ├── database/         # 数据库文件
│   │   │   └── app.db        # SQLite数据库
│   │   ├── __init__.py       # 应用初始化
│   │   └── main.py           # 应用入口文件
│   ├── requirements.txt      # 依赖包列表
│   └── README.md             # 认证服务说明文档
├── frontend/                 # 前端应用
│   ├── index.html           # 主应用界面
│   └── login.html           # 登录页面
├── subsystems/              # 子系统页面
│   ├── bas.html             # 楼宇自控系统
│   ├── security.html        # 安防监控系统
│   ├── fire.html            # 消防报警系统
│   ├── energy.html          # 能源管理系统
│   ├── parking.html         # 停车管理系统
│   ├── public_address.html  # 公共广播系统
│   ├── knowledge_base.html  # 知识库系统
│   └── settings.html        # 系统设置
├── start_backend.bat        # Windows后端启动脚本
├── start_frontend.bat       # Windows前端启动脚本
├── start_backend.sh         # Linux/Mac后端启动脚本
├── start_frontend.sh        # Linux/Mac前端启动脚本
└── README.md                # 项目说明文档
```

## 快速开始

### 方法一：使用启动脚本（推荐）

**Windows用户：**
1. 双击运行 `start_backend.bat` 启动后端服务
2. 双击运行 `start_frontend.bat` 启动前端应用

**Linux/Mac用户：**
1. 在终端运行 `./start_backend.sh` 启动后端服务
2. 在终端运行 `./start_frontend.sh` 启动前端应用

### 方法二：手动启动

#### 1. 启动后端认证服务

```bash
cd auth_service
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate     # Windows

pip install -r requirements.txt
python src/main.py
```

服务将在 http://localhost:5000 启动

#### 2. 启动前端应用

```bash
cd frontend
python3 -m http.server 8080
```

应用将在 http://localhost:8080 启动

#### 3. 访问系统

打开浏览器访问 http://localhost:8080

默认管理员账户：
- 用户名：admin
- 密码：admin123

## 功能特性

- **用户认证**：JWT令牌认证，支持用户注册、登录和权限管理
- **系统管理**：管理员可以管理用户、查看系统统计和配置
- **子系统集成**：通过iframe技术集成多个独立子系统
- **知识库代理**：自动登录外部知识库系统并代理内容
- **响应式设计**：支持桌面和移动设备访问

## 技术栈

- **后端**：Flask + SQLAlchemy + JWT
- **前端**：原生HTML + CSS + JavaScript
- **数据库**：SQLite（可升级到PostgreSQL/MySQL）
- **认证**：JWT令牌 + bcrypt密码加密

## 部署指南

详细的部署指南请参考 `IBMS智能建筑管理系统 - 完整部署指南.md` 