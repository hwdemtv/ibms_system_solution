from functools import wraps
from flask import request, jsonify
import jwt
from flask import current_app

def admin_required(f):
    """
    装饰器：要求管理员权限
    用于保护只有管理员才能访问的API接口
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # 从请求头获取token
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Token格式错误!'}), 401

        if not token:
            return jsonify({'message': 'Token缺失!'}), 401

        try:
            # 解码JWT token
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data.get('user_id')
            current_user_role = data.get('role')
            
            # 检查是否为管理员
            if current_user_role != 'admin':
                return jsonify({'message': '权限不足：需要管理员权限!'}), 403
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token已过期!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token无效!'}), 401

        return f(*args, **kwargs)
    return decorated_function

def token_required(f):
    """
    装饰器：要求有效的token
    用于保护需要登录才能访问的API接口
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # 从请求头获取token
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Token格式错误!'}), 401

        if not token:
            return jsonify({'message': 'Token缺失!'}), 401

        try:
            # 解码JWT token
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data.get('user_id')
            current_user_role = data.get('role')
            
            # 将用户信息传递给被装饰的函数
            return f(current_user_id, current_user_role, *args, **kwargs)
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token已过期!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token无效!'}), 401

    return decorated_function

