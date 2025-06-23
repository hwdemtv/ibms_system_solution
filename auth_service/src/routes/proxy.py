from flask import Blueprint, request, jsonify, session
from flask_cors import cross_origin
import requests
from urllib.parse import urljoin
import re

proxy_bp = Blueprint('proxy', __name__)

# Blinko网站的基础URL
BLINKO_BASE_URL = 'http://bk.hubinwei.top'
LOGIN_CREDENTIALS = {
    'username': 'hwdemtv',
    'password': '8800257'
}

@proxy_bp.route('/blinko-login', methods=['POST'])
@cross_origin()
def blinko_login():
    """
    代理登录Blinko系统
    """
    try:
        # 创建session
        s = requests.Session()
        
        # 首先访问登录页面获取必要的token或cookie
        login_page_response = s.get(f'{BLINKO_BASE_URL}/')
        
        if login_page_response.status_code != 200:
            return jsonify({
                'success': False,
                'message': '无法访问Blinko网站'
            }), 400
        
        # 分析登录页面，查找登录表单的action和必要字段
        login_page_content = login_page_response.text
        
        # 查找登录表单的action URL
        form_action_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', login_page_content)
        if form_action_match:
            login_url = urljoin(BLINKO_BASE_URL, form_action_match.group(1))
        else:
            # 如果没找到form action，尝试常见的登录端点
            login_url = f'{BLINKO_BASE_URL}/api/auth/login'
        
        # 查找CSRF token或其他隐藏字段
        csrf_token_match = re.search(r'<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']*)["\']', login_page_content)
        csrf_token = csrf_token_match.group(1) if csrf_token_match else None
        
        # 准备登录数据
        login_data = {
            'username': LOGIN_CREDENTIALS['username'],
            'password': LOGIN_CREDENTIALS['password']
        }
        
        if csrf_token:
            login_data['_token'] = csrf_token
        
        # 尝试多种登录方式
        login_methods = [
            # 方法1: POST到表单action
            {'url': login_url, 'data': login_data},
            # 方法2: POST到/login
            {'url': f'{BLINKO_BASE_URL}/login', 'data': login_data},
            # 方法3: POST到/api/auth/login (API方式)
            {'url': f'{BLINKO_BASE_URL}/api/auth/login', 'data': login_data},
            # 方法4: POST到/auth/login
            {'url': f'{BLINKO_BASE_URL}/auth/login', 'data': login_data}
        ]
        
        login_success = False
        for method in login_methods:
            try:
                # 尝试表单提交
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Referer': f'{BLINKO_BASE_URL}/',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                login_response = s.post(method['url'], data=method['data'], headers=headers, allow_redirects=False)
                
                # 检查登录是否成功
                if (login_response.status_code in [200, 302, 303] and 
                    ('dashboard' in login_response.text.lower() or 
                     'welcome' in login_response.text.lower() or
                     'logout' in login_response.text.lower() or
                     login_response.status_code in [302, 303])):
                    login_success = True
                    break
                    
                # 尝试JSON格式
                headers['Content-Type'] = 'application/json'
                login_response = s.post(method['url'], json=method['data'], headers=headers, allow_redirects=False)
                
                if (login_response.status_code in [200, 302, 303] and 
                    ('success' in login_response.text.lower() or 
                     'token' in login_response.text.lower() or
                     login_response.status_code in [302, 303])):
                    login_success = True
                    break
                    
            except Exception as e:
                continue
        
        if not login_success:
            return jsonify({
                'success': False,
                'message': '登录失败，请检查凭据或网站状态'
            }), 400
        
        # 获取登录后的cookies
        cookies = s.cookies.get_dict()
        
        # 存储session信息
        session['blinko_cookies'] = cookies
        session['blinko_logged_in'] = True
        
        return jsonify({
            'success': True,
            'message': '登录成功',
            'cookies': cookies
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'登录过程中发生错误: {str(e)}'
        }), 500

@proxy_bp.route('/blinko-proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@cross_origin()
def blinko_proxy(path):
    """
    代理所有对Blinko的请求，自动携带登录cookies
    """
    try:
        # 检查是否已登录
        if not session.get('blinko_logged_in'):
            return jsonify({
                'success': False,
                'message': '请先登录'
            }), 401
        
        # 构建目标URL
        target_url = f'{BLINKO_BASE_URL}/{path}'
        
        # 获取存储的cookies
        cookies = session.get('blinko_cookies', {})
        
        # 转发请求
        if request.method == 'GET':
            response = requests.get(target_url, cookies=cookies, params=request.args)
        elif request.method == 'POST':
            if request.is_json:
                response = requests.post(target_url, json=request.json, cookies=cookies)
            else:
                response = requests.post(target_url, data=request.form, cookies=cookies)
        elif request.method == 'PUT':
            if request.is_json:
                response = requests.put(target_url, json=request.json, cookies=cookies)
            else:
                response = requests.put(target_url, data=request.form, cookies=cookies)
        elif request.method == 'DELETE':
            response = requests.delete(target_url, cookies=cookies)
        
        # 返回响应
        return response.content, response.status_code, dict(response.headers)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'代理请求失败: {str(e)}'
        }), 500

@proxy_bp.route('/blinko-status', methods=['GET'])
@cross_origin()
def blinko_status():
    """
    检查Blinko登录状态
    """
    return jsonify({
        'logged_in': session.get('blinko_logged_in', False),
        'cookies': session.get('blinko_cookies', {})
    })

