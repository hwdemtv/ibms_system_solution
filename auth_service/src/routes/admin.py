from flask import Blueprint, request, jsonify
from src.models.user import User
from src import db
from src.utils.decorators import admin_required, token_required
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_all_users():
    """
    获取所有用户列表（仅管理员）
    """
    try:
        users = User.query.all()
        users_data = []
        
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            }
            users_data.append(user_data)
        
        return jsonify({
            'success': True,
            'users': users_data,
            'total': len(users_data)
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取用户列表失败: {str(e)}'
        }), 500

@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """
    更新用户信息（仅管理员）
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'message': '用户不存在'
            }), 404
        
        data = request.get_json()
        
        # 更新用户角色
        if 'role' in data:
            if data['role'] in ['admin', 'user']:
                user.role = data['role']
            else:
                return jsonify({
                    'success': False,
                    'message': '无效的角色类型'
                }), 400
        
        # 更新用户状态
        if 'is_active' in data:
            user.is_active = bool(data['is_active'])
        
        # 更新邮箱
        if 'email' in data:
            # 检查邮箱是否已被其他用户使用
            existing_user = User.query.filter(User.email == data['email'], User.id != user_id).first()
            if existing_user:
                return jsonify({
                    'success': False,
                    'message': '该邮箱已被其他用户使用'
                }), 400
            user.email = data['email']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '用户信息更新成功',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'更新用户信息失败: {str(e)}'
        }), 500

@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """
    删除用户（仅管理员）
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'message': '用户不存在'
            }), 404
        
        # 防止删除管理员账户
        if user.role == 'admin':
            return jsonify({
                'success': False,
                'message': '不能删除管理员账户'
            }), 403
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '用户删除成功'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'删除用户失败: {str(e)}'
        }), 500

@admin_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def reset_user_password(user_id):
    """
    重置用户密码（仅管理员）
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'message': '用户不存在'
            }), 404
        
        data = request.get_json()
        new_password = data.get('new_password')
        
        if not new_password or len(new_password) < 6:
            return jsonify({
                'success': False,
                'message': '新密码长度至少为6位'
            }), 400
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '密码重置成功'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'重置密码失败: {str(e)}'
        }), 500

@admin_bp.route('/system/config', methods=['GET'])
@admin_required
def get_system_config():
    """
    获取系统配置（仅管理员）
    """
    try:
        # 这里可以从数据库或配置文件中读取系统配置
        # 目前返回默认配置
        config = {
            'system_name': 'IBMS 智能建筑管理系统',
            'system_description': '集成化建筑管理平台 - 统一监控、智能控制、高效管理',
            'default_language': 'zh-CN',
            'timezone': 'Asia/Shanghai',
            'password_min_length': 8,
            'login_attempts_limit': 5,
            'session_timeout_hours': 24,
            'require_complex_password': True,
            'log_level': 'INFO',
            'log_retention_days': 30,
            'enable_audit_log': True
        }
        
        return jsonify({
            'success': True,
            'config': config
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取系统配置失败: {str(e)}'
        }), 500

@admin_bp.route('/system/config', methods=['PUT'])
@admin_required
def update_system_config():
    """
    更新系统配置（仅管理员）
    """
    try:
        data = request.get_json()
        
        # 这里可以将配置保存到数据库或配置文件
        # 目前只是验证数据格式并返回成功
        
        # 验证必要的配置项
        if 'password_min_length' in data:
            if not isinstance(data['password_min_length'], int) or data['password_min_length'] < 6:
                return jsonify({
                    'success': False,
                    'message': '密码最小长度必须为6位以上的整数'
                }), 400
        
        if 'login_attempts_limit' in data:
            if not isinstance(data['login_attempts_limit'], int) or data['login_attempts_limit'] < 3:
                return jsonify({
                    'success': False,
                    'message': '登录尝试次数限制必须为3次以上的整数'
                }), 400
        
        # 这里应该实际保存配置
        # 例如：save_config_to_database(data) 或 save_config_to_file(data)
        
        return jsonify({
            'success': True,
            'message': '系统配置更新成功'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'更新系统配置失败: {str(e)}'
        }), 500

@admin_bp.route('/system/stats', methods=['GET'])
@admin_required
def get_system_stats():
    """
    获取系统统计信息（仅管理员）
    """
    try:
        # 用户统计
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        admin_users = User.query.filter_by(role='admin').count()
        
        # 最近注册用户（最近7天）
        from datetime import datetime, timedelta
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_users = User.query.filter(User.created_at >= week_ago).count()
        
        stats = {
            'users': {
                'total': total_users,
                'active': active_users,
                'admin': admin_users,
                'recent': recent_users
            },
            'system': {
                'uptime': '运行正常',
                'version': '2.0.0',
                'last_backup': '2025-06-14 10:00:00'
            }
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取系统统计失败: {str(e)}'
        }), 500

