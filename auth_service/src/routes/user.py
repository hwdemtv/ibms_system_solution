from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import jwt
from src.models.user import User
from src.utils.decorators import token_required
from src import db

user_bp = Blueprint('user', __name__)

@user_bp.route('/register', methods=['POST'])
def register():
    """用户注册接口"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': '缺少必要参数'}), 400
    
    username = data['username']
    email = data['email']
    password = data['password']
    
    # 检查用户名是否已存在
    if User.query.filter_by(username=username).first():
        return jsonify({'message': '用户名已存在'}), 400
    
    # 检查邮箱是否已存在
    if User.query.filter_by(email=email).first():
        return jsonify({'message': '邮箱已被注册'}), 400
    
    # 创建新用户
    new_user = User(
        username=username,
        email=email,
        role='user'
    )
    new_user.set_password(password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': '注册成功'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '注册失败'}), 500

@user_bp.route('/login', methods=['POST'])
def login():
    """用户登录接口"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': '缺少用户名或密码'}), 400
    
    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'message': '用户名或密码错误'}), 401
    
    if not user.is_active:
        return jsonify({'message': '账户已被禁用'}), 403
    
    # 更新最后登录时间
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # 生成JWT令牌
    token = jwt.encode({
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, current_app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
    }), 200

@user_bp.route('/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    """令牌验证接口"""
    return jsonify({
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'role': current_user.role
        }
    }), 200

@user_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """获取用户资料"""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role,
        'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
        'last_login': current_user.last_login.isoformat() if current_user.last_login else None
    }), 200

@user_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    """更新用户资料"""
    data = request.get_json()
    
    if not data:
        return jsonify({'message': '缺少更新数据'}), 400
    
    # 更新邮箱
    if 'email' in data:
        email = data['email']
        if email != current_user.email:
            if User.query.filter_by(email=email).first():
                return jsonify({'message': '邮箱已被使用'}), 400
            current_user.email = email
    
    # 更新密码
    if 'password' in data and data['password']:
        current_user.set_password(data['password'])
    
    try:
        db.session.commit()
        return jsonify({'message': '资料更新成功'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '资料更新失败'}), 500 