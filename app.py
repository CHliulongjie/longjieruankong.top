import os
import uuid
import json
import logging
import shutil
from datetime import datetime
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
from flask import render_template_string
import ssl
from waitress import create_server
from flask import render_template
import traceback
import pandas as pd


# ==================== 配置区域 ====================
class Config:
    HOST = '127.0.0.1'
    PORT = 8000
    DEBUG = False  # 生产环境设为 False

    # 文件大小限制 (100MB)
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

    # 文件路径配置
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ENCRYPTED_FOLDER = os.path.join(BASE_DIR, 'encrypted')
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')

    # Waitress 服务器配置
    WAITRESS_THREADS = 4
    WAITRESS_CHANNEL_TIMEOUT = 120  # 2分钟超时

    # 创建必要目录
    for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, LOG_FOLDER]:
        os.makedirs(folder, exist_ok=True)


# ==================== 支持中文密码的加密器类 ====================
class FileEncryptor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def string_to_hex(self, text):
        """将字符串（支持中文）转换为16进制字符串"""
        try:
            # 使用UTF-8编码处理中文字符
            return text.encode('utf-8').hex().upper()
        except Exception as e:
            self.logger.error(f"字符串转16进制失败: {e}")
            # 如果UTF-8编码失败，尝试其他编码
            try:
                return text.encode('gbk').hex().upper()
            except:
                return text.encode('utf-8', errors='ignore').hex().upper()

    def hex_to_string(self, hex_str):
        """将16进制字符串转换回字符串（支持中文）"""
        try:
            # 尝试UTF-8解码
            return bytes.fromhex(hex_str).decode('utf-8')
        except UnicodeDecodeError:
            # 如果UTF-8失败，尝试GBK解码
            try:
                return bytes.fromhex(hex_str).decode('gbk')
            except:
                return None
        except:
            return None

    def file_to_hex(self, file_path):
        """将文件内容转换为16进制字符串"""
        with open(file_path, 'rb') as f:
            content = f.read()
        return content.hex().upper()

    def hex_to_file(self, hex_str, output_path):
        """将16进制字符串写回文件"""
        try:
            # 移除可能存在的无效字符
            hex_str = ''.join(c for c in hex_str if c in '0123456789ABCDEFabcdef')

            # 确保长度为偶数
            if len(hex_str) % 2 != 0:
                hex_str = hex_str[:-1]

            content = bytes.fromhex(hex_str)
            with open(output_path, 'wb') as f:
                f.write(content)
            self.logger.info(f"成功写入文件: {output_path}, 大小: {len(content)} 字节")
            return True
        except Exception as e:
            self.logger.error(f"hex_to_file 失败: {e}")
            return False

    def pad_hex_group(self, hex_str, target_length):
        """将16进制字符串填充到目标长度"""
        if len(hex_str) >= target_length:
            return hex_str[-target_length:]
        return hex_str + '0' * (target_length - len(hex_str))

    def hex_addition(self, hex1, hex2):
        """16进制加法 - 使用循环算法保证可逆性"""
        # 确保两个十六进制字符串长度一致，以较长者为准
        max_len = max(len(hex1), len(hex2))
        hex1_padded = hex1.zfill(max_len)
        hex2_padded = hex2.zfill(max_len)
        
        # 转换为整数进行加法运算
        num1 = int(hex1_padded, 16)
        num2 = int(hex2_padded, 16)
        
        # 使用模运算，模数为 16^max_len，保证结果在相同长度范围内
        result = (num1 + num2) % (16 ** max_len)
        
        # 将结果转换回十六进制并填充到指定长度
        result_hex = format(result, f'0{max_len}X')  # 使用大写十六进制
        return result_hex

    def hex_subtraction(self, hex1, hex2):
        """16进制减法 - 与加法完全可逆"""
        # 确保两个十六进制字符串长度一致，以较长者为准
        max_len = max(len(hex1), len(hex2))
        hex1_padded = hex1.zfill(max_len)
        hex2_padded = hex2.zfill(max_len)
        
        # 转换为整数进行减法运算
        num1 = int(hex1_padded, 16)
        num2 = int(hex2_padded, 16)
        
        # 使用模运算，模数为 16^max_len，保证结果在相同长度范围内
        result = (num1 - num2) % (16 ** max_len)
        
        # 将结果转换回十六进制并填充到指定长度
        result_hex = format(result, f'0{max_len}X')  # 使用大写十六进制
        return result_hex

    def separate_odd_even(self, hex_str):
        """分离奇偶位"""
        odd = ''.join(hex_str[i] for i in range(0, len(hex_str), 2))
        even = ''.join(hex_str[i] for i in range(1, len(hex_str), 2))
        return odd, even

    def combine_odd_even(self, odd, even):
        """合并奇偶位"""
        result = []
        min_len = min(len(odd), len(even))
        for i in range(min_len):
            result.append(odd[i])
            result.append(even[i])
        if len(odd) > min_len:
            result.append(odd[min_len:])
        elif len(even) > min_len:
            result.append(even[min_len:])
        return ''.join(result)

    def validate_password(self, password):
        """验证密码有效性（支持中文）"""
        if not password:
            return False, "密码不能为空"

        # 计算字符数（不是字节数），支持中文字符
        char_count = len(password)
        if char_count < 4:
            return False, "密码长度至少4个字符"

        # 检查密码是否只包含空白字符
        if password.strip() == "":
            return False, "密码不能只包含空白字符"

        return True, "密码有效"

    def encrypt_file(self, file_path, password, output_path):
        """加密文件（支持中文密码）"""
        try:
            # 验证密码
            is_valid, msg = self.validate_password(password)
            if not is_valid:
                raise ValueError(msg)

            # 1. 获取文件后缀名
            file_ext = os.path.splitext(file_path)[1]
            ext_hex = self.string_to_hex(file_ext)
            self.logger.info(f"文件后缀: {file_ext} -> 16进制: {ext_hex}")

            # 2. 将源文件转换为16进制
            file_hex = self.file_to_hex(file_path)
            self.logger.info(f"文件16进制长度: {len(file_hex)}")

            # 3. 将密码转换为16进制（支持中文）
            password_hex = self.string_to_hex(password)
            n = len(password_hex)
            self.logger.info(f"密码字符数: {len(password)}, 16进制长度: {n}, 16进制: {password_hex}")

            if n == 0:
                raise ValueError("密码转换后为空")

            # 4. 分组处理
            groups = []
            for i in range(0, len(file_hex), n):
                group = file_hex[i:i + n]
                if len(group) < n:
                    group = self.pad_hex_group(group, n)
                groups.append(group)

            self.logger.info(f"分为 {len(groups)} 组，每组 {n} 位")

            # 5. 每组与密码相加
            encrypted_groups = []
            for group in groups:
                encrypted_group = self.hex_addition(group, password_hex)
                if len(encrypted_group) < n + 1:
                    encrypted_group = '0' * (n + 1 - len(encrypted_group)) + encrypted_group
                encrypted_groups.append(encrypted_group)

            # 6. 添加后缀名组
            encrypted_ext = self.hex_addition(ext_hex, password_hex)
            if len(encrypted_ext) < n + 1:
                encrypted_ext = '0' * (n + 1 - len(encrypted_ext)) + encrypted_ext

            all_groups = [encrypted_ext] + encrypted_groups
            full_encrypted_hex = ''.join(all_groups)

            # 7. 分离奇偶位
            odd, even = self.separate_odd_even(full_encrypted_hex)
            final_result = odd + "." + even

            # 8. 保存文件
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(final_result)

            self.logger.info(f"加密文件保存成功: {output_path}")

            return {
                'success': True,
                'original_size': len(file_hex) // 2,
                'encrypted_size': len(final_result)
            }

        except Exception as e:
            self.logger.error(f"加密失败: {e}")
            if os.path.exists(output_path):
                os.remove(output_path)
            return {'success': False, 'error': str(e)}

    def decrypt_file(self, file_path, password, output_path):
        """解密文件（支持中文密码）"""
        try:
            self.logger.info(f"开始解密文件: {file_path}")

            # 验证密码
            is_valid, msg = self.validate_password(password)
            if not is_valid:
                raise ValueError(msg)

            # 1. 读取加密文件
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"加密文件不存在: {file_path}")

            with open(file_path, 'r', encoding='utf-8') as f:
                encrypted_content = f.read().strip()

            if '.' not in encrypted_content:
                raise ValueError("无效的加密文件格式")

            odd, even = encrypted_content.split('.', 1)
            full_encrypted_hex = self.combine_odd_even(odd, even)

            self.logger.info(f"合并奇偶位后长度: {len(full_encrypted_hex)}")

            # 2. 密码处理（支持中文）
            password_hex = self.string_to_hex(password)
            n = len(password_hex)
            group_size = n + 1

            if n == 0:
                raise ValueError("密码转换后为空")

            # 3. 分组处理
            if len(full_encrypted_hex) < group_size:
                raise ValueError("加密文件长度不足")

            ext_group = full_encrypted_hex[:group_size]
            content_groups_hex = full_encrypted_hex[group_size:]

            content_groups = []
            for i in range(0, len(content_groups_hex), group_size):
                group = content_groups_hex[i:i + group_size]
                if len(group) == group_size:
                    content_groups.append(group)

            self.logger.info(f"总组数: {len(content_groups) + 1}")

            # 4. 解密后缀名
            decrypted_ext_hex = self.hex_subtraction(ext_group, password_hex)
            decrypted_ext_hex = decrypted_ext_hex.lstrip('0') or '0'
            file_ext = self.hex_to_string(decrypted_ext_hex)

            if file_ext is None:
                file_ext = "." + decrypted_ext_hex[:10]

            self.logger.info(f"解密得到后缀名: {file_ext}")

            # 5. 解密文件内容
            decrypted_content_hex = ""
            for group in content_groups:
                decrypted_group = self.hex_subtraction(group, password_hex)
                if len(decrypted_group) < n:
                    decrypted_group = '0' * (n - len(decrypted_group)) + decrypted_group
                elif len(decrypted_group) > n:
                    decrypted_group = decrypted_group[-n:]
                decrypted_content_hex += decrypted_group

            self.logger.info(f"解密后16进制长度: {len(decrypted_content_hex)}")

            # 6. 转换回文件
            success = self.hex_to_file(decrypted_content_hex, output_path)

            if not success:
                # 如果失败，尝试逐步调整长度
                for i in range(len(decrypted_content_hex), 0, -2):
                    try:
                        test_hex = decrypted_content_hex[:i]
                        if self.hex_to_file(test_hex, output_path):
                            if os.path.getsize(output_path) > 0:
                                self.logger.info(f"成功转换，有效长度: {i}")
                                success = True
                                break
                    except Exception:
                        continue

            if not success:
                raise ValueError("文件内容转换失败")

            # 7. 处理文件后缀
            final_output_path = output_path
            if file_ext:
                # 创建带后缀的新路径
                new_output_path = output_path + file_ext
                if os.path.exists(output_path):
                    # 重命名文件
                    os.rename(output_path, new_output_path)
                    final_output_path = new_output_path
                    self.logger.info(f"文件重命名为: {final_output_path}")

            self.logger.info(f"解密成功，最终文件: {final_output_path}")

            # 检查文件是否存在且不为空
            if not os.path.exists(final_output_path) or os.path.getsize(final_output_path) == 0:
                raise ValueError("解密后的文件无效")

            return {
                'success': True,
                'file_ext': file_ext,
                'final_path': final_output_path
            }

        except Exception as e:
            self.logger.error(f"解密失败: {e}")
            # 清理可能创建的文件
            for path in [output_path, output_path + '.tmp']:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except:
                        pass
            return {'success': False, 'error': str(e)}


def init_excel_file():
    file_path = 'data.xlsx'
    if not os.path.exists(file_path):
        # 创建新的Excel文件
        df = pd.DataFrame(columns=['提交时间', '班级', '姓名', '联系方式', '编程经验'])
        df.to_excel(file_path, index=False)
        print(f"创建新的Excel文件: {file_path}")
    else:
        print(f"Excel文件已存在: {file_path}")

# 初始化Excel文件
init_excel_file()

# ==================== Flask应用 ====================
app = Flask(__name__)
app.config.from_object(Config)

# 设置文件大小限制
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

# 启用CORS
CORS(app)

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(Config.LOG_FOLDER, 'app.log')),
        logging.StreamHandler()
    ]
)

# 初始化加密器
encryptor = FileEncryptor()


# ==================== 工具函数 ====================
def secure_filename(filename):
    """安全的文件名处理"""
    filename = os.path.basename(filename)
    for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|']:
        filename = filename.replace(char, '_')
    return filename


def generate_file_id():
    """生成唯一文件ID"""
    return str(uuid.uuid4())


def cleanup_file(file_path):
    """安全地清理文件"""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            app.logger.info(f"清理文件: {file_path}")
            return True
    except Exception as e:
        app.logger.error(f"清理文件失败 {file_path}: {e}")
    return False



# ==================== 支持中文密码的HTML界面 ====================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>龙解软控—文件加密解密系统</title>
    <style>
        :root {
            --primary: #4361ee;
            --primary-dark: #3a56d4;
            --secondary: #7209b7;
            --success: #4cc9f0;
            --danger: #f72585;
            --light: #f8f9fa;
            --dark: #212529;
            --gray: #6c757d;
            --border: #dee2e6;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: var(--dark);
            line-height: 1.6;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
        }

        .header h1 {
            font-size: 2.8rem;
            margin-bottom: 10px;
            font-weight: 700;
            position: relative;
        }

        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
            max-width: 600px;
            margin: 0 auto;
            position: relative;
        }

        .content {
            padding: 30px;
        }

        .tabs {
            display: flex;
            margin-bottom: 30px;
            border-bottom: 2px solid var(--border);
            background: #f8f9fa;
            border-radius: 10px 10px 0 0;
            overflow: hidden;
        }

        .tab {
            flex: 1;
            padding: 18px 20px;
            cursor: pointer;
            border: none;
            background: transparent;
            font-size: 1.1rem;
            color: var(--gray);
            transition: var(--transition);
            text-align: center;
            font-weight: 500;
            position: relative;
        }

        .tab:hover {
            background: rgba(67, 97, 238, 0.05);
            color: var(--primary);
        }

        .tab.active {
            color: var(--primary);
            font-weight: 600;
        }

        .tab.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--primary);
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card {
            background: white;
            border-radius: 15px;
            box-shadow: var(--shadow);
            padding: 30px;
            margin-bottom: 25px;
            border: 1px solid var(--border);
            transition: var(--transition);
        }

        .card:hover {
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }

        .card-title {
            font-size: 1.4rem;
            color: var(--primary);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
        }

        .card-title i {
            margin-right: 10px;
            font-size: 1.6rem;
        }

        .upload-area {
            border: 3px dashed #cbd5e0;
            border-radius: 12px;
            padding: 50px 30px;
            text-align: center;
            margin-bottom: 25px;
            transition: var(--transition);
            background: #fafbfc;
            cursor: pointer;
            position: relative;
        }

        .upload-area:hover {
            border-color: var(--primary);
            background: #f0f4ff;
        }

        .upload-area.dragover {
            background: #e3f2fd;
            border-color: var(--primary);
            transform: scale(1.02);
        }

        .upload-area i {
            font-size: 64px;
            color: var(--primary);
            margin-bottom: 20px;
            display: block;
        }

        .upload-area h3 {
            font-size: 1.5rem;
            margin-bottom: 10px;
            color: var(--dark);
        }

        .upload-area p {
            color: var(--gray);
            font-size: 1rem;
        }

        .file-input {
            display: none;
        }

        .btn {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            border: none;
            padding: 14px 32px;
            border-radius: 50px;
            cursor: pointer;
            font-size: 1.1rem;
            transition: var(--transition);
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 15px rgba(67, 97, 238, 0.3);
        }

        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(67, 97, 238, 0.4);
        }

        .btn:active {
            transform: translateY(-1px);
        }

        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .btn i {
            margin-right: 8px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--dark);
        }

        .password-container {
            position: relative;
            display: flex;
            align-items: center;
        }

        /* 关键修改：使用text类型输入框，但显示为圆点 */
        .password-input {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 1rem;
            transition: var(--transition);
            padding-right: 50px; /* 为切换按钮留出空间 */
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif; /* 统一字体 */
        }

        /* 密码输入框显示为圆点 */
        .password-input.masked {
            -webkit-text-security: disc; /* Webkit浏览器 */
            -moz-text-security: disc; /* Firefox */
            text-security: disc; /* 标准属性 */
        }

        .password-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.1);
        }

        .password-toggle {
            position: absolute;
            right: 15px;
            background: none;
            border: none;
            cursor: pointer;
            color: var(--gray);
            font-size: 1.2rem;
            padding: 5px;
            border-radius: 3px;
            transition: var(--transition);
        }

        .password-toggle:hover {
            background-color: rgba(0, 0, 0, 0.05);
            color: var(--primary);
        }

        .password-match {
            color: #38a169;
            font-size: 0.9rem;
            margin-top: 5px;
            display: none;
        }

        .password-mismatch {
            color: #e53e3e;
            font-size: 0.9rem;
            margin-top: 5px;
            display: none;
        }

        .password-info {
            color: var(--gray);
            font-size: 0.8rem;
            margin-top: 5px;
        }

        .file-info {
            background: #f7fafc;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border-left: 4px solid var(--primary);
        }

        .file-name {
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 5px;
        }

        .file-meta {
            color: var(--gray);
            font-size: 0.9rem;
        }

        .progress-container {
            margin: 25px 0;
            display: none;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 10px;
        }

        .progress {
            height: 100%;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            width: 0%;
            transition: width 0.4s ease;
            border-radius: 4px;
        }

        .progress-text {
            text-align: center;
            font-size: 0.9rem;
            color: var(--gray);
        }

        .message {
            padding: 15px 20px;
            border-radius: 10px;
            margin: 20px 0;
            display: none;
            animation: slideIn 0.3s ease;
        }

        .message.success {
            background: #f0fff4;
            color: #2d7d32;
            border: 1px solid #9ae6b4;
        }

        .message.error {
            background: #fed7d7;
            color: #c53030;
            border: 1px solid #fc8181;
        }

        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            color: var(--gray);
            font-size: 0.9rem;
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* 响应式设计 */
        @media (max-width: 768px) {
            .container {
                border-radius: 0;
            }

            .header {
                padding: 30px 20px;
            }

            .header h1 {
                font-size: 2.2rem;
            }

            .content {
                padding: 20px;
            }

            .tabs {
                flex-direction: column;
            }

            .upload-area {
                padding: 30px 20px;
            }

            .upload-area i {
                font-size: 48px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 文件加密解密系统</h1>
            <p>由龙解软控设计算法并搭建的加密解密系统</p>
        </div>

        <div class="content">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('encrypt')">
                    <i>🔒</i> 加密文件
                </button>
                <button class="tab" onclick="switchTab('decrypt')">
                    <i>🔓</i> 解密文件
                </button>
            </div>

            <!-- 加密标签页 -->
            <div id="encrypt" class="tab-content active">
                <div class="card">
                    <h2 class="card-title"><i>📁</i> 手动上传文件进行加密</h2>

                    <div class="upload-area" id="encryptUploadArea" onclick="document.getElementById('encryptFile').click()">
                        <i>📤</i>
                        <h3>拖放文件到此处或点击选择</h3>
                        <p>支持所有类型的文件，最大100MB</p>
                        <input type="file" id="encryptFile" class="file-input" />
                    </div>

                    <div id="encryptFileInfo" class="file-info" style="display: none;">
                        <div class="file-name" id="fileName"></div>
                        <div class="file-meta" id="fileSize">文件大小: 计算中...</div>
                    </div>
                </div>

                <div class="card">
                    <h2 class="card-title"><i>🔑</i> 设置加密密码</h2>

                    <div class="form-group">
                        <label class="form-label" for="encryptPassword">加密密码</label>
                        <div class="password-container">
                            <!-- 关键修改：使用text类型输入框，但通过CSS显示为圆点 -->
                            <input type="text" id="encryptPassword" class="password-input masked" placeholder="请输入加密密码（支持中文，至少4个字符）" autocomplete="off" />
                            <button type="button" class="password-toggle" onclick="togglePasswordVisibility('encryptPassword')">👁️</button>
                        </div>
                        <div class="password-info">💡 支持中文、英文、数字和符号，至少4个字符</div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="encryptPasswordConfirm">确认密码</label>
                        <div class="password-container">
                            <input type="text" id="encryptPasswordConfirm" class="password-input masked" placeholder="请再次输入密码确认" autocomplete="off" />
                            <button type="button" class="password-toggle" onclick="togglePasswordVisibility('encryptPasswordConfirm')">👁️</button>
                        </div>
                        <div class="password-match" id="passwordMatch">✓ 密码匹配</div>
                        <div class="password-mismatch" id="passwordMismatch">✗ 密码不匹配</div>
                    </div>

                    <div class="progress-container" id="encryptProgressContainer">
                        <div class="progress-bar">
                            <div class="progress" id="encryptProgress"></div>
                        </div>
                        <div class="progress-text" id="encryptProgressText">准备加密...</div>
                    </div>

                    <button class="btn" id="encryptBtn" onclick="encryptFile()" disabled>
                        <i>🔒</i> 开始加密
                    </button>

                    <div class="message" id="encryptMessage"></div>
                </div>
            </div>

            <!-- 解密标签页 -->
            <div id="decrypt" class="tab-content">
                <div class="card">
                    <h2 class="card-title"><i>📁</i> 选择要解密的文件</h2>

                    <div class="upload-area" id="decryptUploadArea" onclick="document.getElementById('decryptFile').click()">
                        <i>📥</i>
                        <h3>选择.ljrk加密文件</h3>
                        <p>请选择之前加密生成的.ljrk文件</p>
                        <input type="file" id="decryptFile" class="file-input" accept=".ljrk" />
                    </div>

                    <div id="decryptFileInfo" class="file-info" style="display: none;">
                        <div class="file-name" id="decryptFileName"></div>
                    </div>
                </div>

                <div class="card">
                    <h2 class="card-title"><i>🔑</i> 输入解密密码</h2>

                    <div class="form-group">
                        <label class="form-label" for="decryptPassword">解密密码</label>
                        <div class="password-container">
                            <input type="text" id="decryptPassword" class="password-input masked" placeholder="请输入解密密码（支持中文）" autocomplete="off" />
                            <button type="button" class="password-toggle" onclick="togglePasswordVisibility('decryptPassword')">👁️</button>
                        </div>
                        <div class="password-info">💡 支持中文、英文、数字和符号</div>
                    </div>

                    <div class="progress-container" id="decryptProgressContainer">
                        <div class="progress-bar">
                            <div class="progress" id="decryptProgress"></div>
                        </div>
                        <div class="progress-text" id="decryptProgressText">准备解密...</div>
                    </div>

                    <button class="btn" id="decryptBtn" onclick="decryptFile()" disabled>
                        <i>🔓</i> 开始解密
                    </button>

                    <div class="message" id="decryptMessage"></div>
                </div>
            </div>

            <div class="footer">
                <p>龙解软控—文件加密解密系统 betav4.0 | 目前仍然处于测试阶段，请保密为主</p>
                <p><a href="https://beian.miit.gov.cn/" target="_blank" style="color: var(--gray); text-decoration: none;">沪ICP备2025145173号-2</a></p>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = '/api';

        // 标签页切换
        function switchTab(tabName) {
            // 隐藏所有标签页内容
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });

            // 移除所有标签的active类
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // 显示选中的标签页
            document.getElementById(tabName).classList.add('active');

            // 激活对应的标签
            event.target.classList.add('active');
        }

        // 初始化拖放功能
        function initDragDrop() {
            const areas = ['encryptUploadArea', 'decryptUploadArea'];

            areas.forEach(areaId => {
                const area = document.getElementById(areaId);
                const fileInput = areaId === 'encryptUploadArea' ? 
                    document.getElementById('encryptFile') : 
                    document.getElementById('decryptFile');

                area.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    area.classList.add('dragover');
                });

                area.addEventListener('dragleave', () => {
                    area.classList.remove('dragover');
                });

                area.addEventListener('drop', (e) => {
                    e.preventDefault();
                    area.classList.remove('dragover');

                    if (e.dataTransfer.files.length) {
                        fileInput.files = e.dataTransfer.files;
                        handleFileSelect(fileInput);
                    }
                });
            });

            // 文件选择事件
            document.getElementById('encryptFile').addEventListener('change', function() {
                handleFileSelect(this);
            });

            document.getElementById('decryptFile').addEventListener('change', function() {
                handleFileSelect(this);
            });

            // 密码输入验证
            document.getElementById('encryptPassword').addEventListener('input', validateEncryptForm);
            document.getElementById('encryptPasswordConfirm').addEventListener('input', validateEncryptForm);
            document.getElementById('decryptPassword').addEventListener('input', validateDecryptForm);
        }

        // 密码显示/隐藏切换
        function togglePasswordVisibility(inputId) {
            const input = document.getElementById(inputId);
            const toggleButton = input.nextElementSibling;

            if (input.classList.contains('masked')) {
                // 当前是隐藏状态，切换为显示
                input.classList.remove('masked');
                toggleButton.textContent = '🔒';
            } else {
                // 当前是显示状态，切换为隐藏
                input.classList.add('masked');
                toggleButton.textContent = '👁️';
            }
        }

        // 处理文件选择
        function handleFileSelect(input) {
            const file = input.files[0];
            if (!file) return;

            const isEncrypt = input.id === 'encryptFile';
            const fileInfoDiv = isEncrypt ? 
                document.getElementById('encryptFileInfo') : 
                document.getElementById('decryptFileInfo');
            const fileNameSpan = isEncrypt ? 
                document.getElementById('fileName') : 
                document.getElementById('decryptFileName');
            const fileSizeP = isEncrypt ? 
                document.getElementById('fileSize') : null;
            const btn = isEncrypt ? 
                document.getElementById('encryptBtn') : 
                document.getElementById('decryptBtn');

            fileNameSpan.textContent = file.name;
            fileInfoDiv.style.display = 'block';

            if (fileSizeP) {
                fileSizeP.textContent = `文件大小: ${formatFileSize(file.size)}`;
            }

            // 验证表单
            if (isEncrypt) {
                validateEncryptForm();
            } else {
                validateDecryptForm();
            }
        }

        // 验证加密表单
        function validateEncryptForm() {
            const file = document.getElementById('encryptFile').files[0];
            const password = document.getElementById('encryptPassword').value;
            const passwordConfirm = document.getElementById('encryptPasswordConfirm').value;
            const btn = document.getElementById('encryptBtn');
            const matchMsg = document.getElementById('passwordMatch');
            const mismatchMsg = document.getElementById('passwordMismatch');

            // 隐藏所有消息
            matchMsg.style.display = 'none';
            mismatchMsg.style.display = 'none';

            // 检查密码匹配
            if (password && passwordConfirm) {
                if (password === passwordConfirm) {
                    if (password.length >= 4) {
                        matchMsg.style.display = 'block';
                    }
                } else {
                    mismatchMsg.style.display = 'block';
                }
            }

            btn.disabled = !file || !password || password !== passwordConfirm || password.length < 4;
        }

        // 验证解密表单
        function validateDecryptForm() {
            const file = document.getElementById('decryptFile').files[0];
            const password = document.getElementById('decryptPassword').value;
            const btn = document.getElementById('decryptBtn');

            btn.disabled = !file || !password;
        }

        // 加密文件
        async function encryptFile() {
            const file = document.getElementById('encryptFile').files[0];
            const password = document.getElementById('encryptPassword').value;
            const passwordConfirm = document.getElementById('encryptPasswordConfirm').value;

            if (password !== passwordConfirm) {
                showMessage('encryptMessage', '密码不匹配，请确认密码', 'error');
                return;
            }

            if (password.length < 4) {
                showMessage('encryptMessage', '密码长度至少4个字符', 'error');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);
            formData.append('password', password);

            showProgress('encryptProgressContainer', 'encryptProgress', 'encryptProgressText', '加密中...');
            disableButton('encryptBtn', '🔒 加密中...');
            hideMessage('encryptMessage');

            try {
                const response = await fetch(`${API_BASE}/encrypt`, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showMessage('encryptMessage', '加密成功！正在下载文件...', 'success');
                    updateProgress('encryptProgress', 'encryptProgressText', 100, '加密完成');

                    // 自动下载加密后的文件
                    setTimeout(() => {
                        const a = document.createElement('a');
                        a.href = `${API_BASE}/download/${result.file_id}`;
                        a.download = result.encrypted_name;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);

                        showMessage('encryptMessage', '加密成功！文件已下载。', 'success');
                        resetEncryptForm();
                    }, 1000);

                } else {
                    showMessage('encryptMessage', result.error || '加密失败', 'error');
                    hideProgress('encryptProgressContainer');
                }
            } catch (error) {
                showMessage('encryptMessage', '网络错误，请检查服务器连接', 'error');
                hideProgress('encryptProgressContainer');
            } finally {
                enableButton('encryptBtn', '🔒 开始加密');
            }
        }

        // 解密文件
        async function decryptFile() {
            const file = document.getElementById('decryptFile').files[0];
            const password = document.getElementById('decryptPassword').value;

            const formData = new FormData();
            formData.append('file', file);
            formData.append('password', password);

            showProgress('decryptProgressContainer', 'decryptProgress', 'decryptProgressText', '解密中...');
            disableButton('decryptBtn', '🔓 解密中...');
            hideMessage('decryptMessage');

            try {
                const response = await fetch(`${API_BASE}/decrypt`, {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    updateProgress('decryptProgress', 'decryptProgressText', 100, '解密完成');

                    // 下载文件
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');

                    // 从Content-Disposition头获取文件名
                    const contentDisposition = response.headers.get('Content-Disposition');
                    let filename = 'decrypted_file';
                    if (contentDisposition) {
                        const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
                        if (filenameMatch) {
                            filename = filenameMatch[1];
                        }
                    }

                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);

                    showMessage('decryptMessage', '解密成功！文件已下载。', 'success');
                    resetDecryptForm();
                } else {
                    const result = await response.json();
                    showMessage('decryptMessage', result.error || '解密失败', 'error');
                    hideProgress('decryptProgressContainer');
                }
            } catch (error) {
                showMessage('decryptMessage', '网络错误，请检查服务器连接', 'error');
                hideProgress('decryptProgressContainer');
            } finally {
                enableButton('decryptBtn', '🔓 开始解密');
            }
        }

        // 工具函数
        function showProgress(containerId, progressId, textId, text) {
            const container = document.getElementById(containerId);
            const progress = document.getElementById(progressId);
            const progressText = document.getElementById(textId);

            container.style.display = 'block';
            progress.style.width = '0%';
            progressText.textContent = text;

            // 模拟进度
            let width = 0;
            const interval = setInterval(() => {
                if (width >= 90) {
                    clearInterval(interval);
                } else {
                    width += Math.random() * 10;
                    progress.style.width = width + '%';
                }
            }, 200);
        }

        function updateProgress(progressId, textId, width, text) {
            const progress = document.getElementById(progressId);
            const progressText = document.getElementById(textId);

            progress.style.width = width + '%';
            progressText.textContent = text;
        }

        function hideProgress(containerId) {
            const container = document.getElementById(containerId);
            container.style.display = 'none';
        }

        function disableButton(btnId, text) {
            const btn = document.getElementById(btnId);
            btn.disabled = true;
            btn.innerHTML = text;
        }

        function enableButton(btnId, text) {
            const btn = document.getElementById(btnId);
            btn.disabled = false;
            btn.innerHTML = text;
        }

        function showMessage(messageId, text, type) {
            const message = document.getElementById(messageId);
            message.textContent = text;
            message.className = `message ${type}`;
            message.style.display = 'block';
        }

        function hideMessage(messageId) {
            document.getElementById(messageId).style.display = 'none';
        }

        function resetEncryptForm() {
            document.getElementById('encryptFile').value = '';
            document.getElementById('encryptPassword').value = '';
            document.getElementById('encryptPasswordConfirm').value = '';
            document.getElementById('encryptFileInfo').style.display = 'none';
            document.getElementById('encryptBtn').disabled = true;
            document.getElementById('passwordMatch').style.display = 'none';
            document.getElementById('passwordMismatch').style.display = 'none';
            hideProgress('encryptProgressContainer');
        }

        function resetDecryptForm() {
            document.getElementById('decryptFile').value = '';
            document.getElementById('decryptPassword').value = '';
            document.getElementById('decryptFileInfo').style.display = 'none';
            document.getElementById('decryptBtn').disabled = true;
            hideProgress('decryptProgressContainer');
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // 初始化中文输入法支持
        function initInputMethodSupport() {
            const passwordInputs = ['encryptPassword', 'encryptPasswordConfirm', 'decryptPassword'];

            passwordInputs.forEach(inputId => {
                const input = document.getElementById(inputId);
                let isComposing = false;

                // 监听输入法开始
                input.addEventListener('compositionstart', function() {
                    isComposing = true;
                });

                // 监听输入法结束
                input.addEventListener('compositionend', function() {
                    isComposing = false;
                });

                // 监听输入事件
                input.addEventListener('input', function() {
                    // 如果正在使用输入法，不触发验证
                    if (isComposing) return;

                    // 延迟验证，确保输入法处理完成
                    setTimeout(() => {
                        if (inputId === 'encryptPassword' || inputId === 'encryptPasswordConfirm') {
                            validateEncryptForm();
                        } else {
                            validateDecryptForm();
                        }
                    }, 100);
                });
            });
        }

        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            initDragDrop();
            initInputMethodSupport();
        });
    </script>
</body>
</html>
"""


# ==================== API路由 ====================
@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta name="msvalidate.01" content="B6794F3429902CFF60787BC0CDF856AE" />
        <meta charset="UTF-8">
        
        <title>龙解软控 - 中国中学算法穹顶社</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Microsoft YaHei', sans-serif; }
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; min-height: 100vh; }
            .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
            .hero { text-align: center; padding: 100px 0; }
            .hero h1 { font-size: 3rem; margin-bottom: 1rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
            .hero p { font-size: 1.2rem; margin-bottom: 2rem; opacity: 0.9; }
            .nav-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin-top: 50px; }
            .nav-card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); padding: 30px; border-radius: 15px; text-align: center; transition: transform 0.3s, background 0.3s; border: 1px solid rgba(255,255,255,0.2); }
            .nav-card:hover { transform: translateY(-10px); background: rgba(255,255,255,0.2); }
            .nav-card h3 { font-size: 1.5rem; margin-bottom: 15px; }
            .nav-card p { margin-bottom: 20px; opacity: 0.8; }
            .btn { display: inline-block; padding: 12px 30px; background: white; color: #667eea; text-decoration: none; border-radius: 25px; font-weight: bold; transition: all 0.3s; }
            .btn:hover { background: #f8f9fa; transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
            .footer { text-align: center; padding: 40px 0; margin-top: 50px; border-top: 1px solid rgba(255,255,255,0.1); }
            .footer a { color: white; text-decoration: none; margin: 0 10px; }
            @media (max-width: 768px) {
                .hero h1 { font-size: 2rem; }
                .nav-grid { grid-template-columns: 1fr; }
            }
        
        </style>
    </head>
    <body>
        <div class="container">
            <div class="hero">
                <h1>龙解软控</h1>
                <p>中国中学算法穹顶社个人代理官网以及中国中学学生软件代理</p>
                <div class="nav-grid">
                    <div class="nav-card">
                        <h3>算法穹顶社官网</h3>
                        <p>中国中学算法穹顶社官方网站</p>
                        <a href="/sfqd-club" class="btn">访问官网</a>
                    </div>
                    <div class="nav-card">
                        <h3>作业管理系统</h3>
                        <p>中国中学作业管理系统介绍</p>
                        <a href="/zgzxhomeworkmgr" class="btn">查看详情</a>
                    </div>
                    <div class="nav-card">
                        <h3>杭台高铁动态运营图</h3>
                        <p>基于12306客票数据分析设计杭台高铁本线工作日开行方案</p>
                        <a href="/htgtmove" class="btn">立即预览</a>
                    </div>
                    <div class="nav-card">
                        <h3>文件加密解密</h3>
                        <p>支持中文密码的文件加密解密服务</p>
                        <a href="/encrypt" class="btn">立即使用</a>
                    </div>
                </div>
            </div>
            <div class="footer">
                <p>© 2025 龙解软控 版权所有 | 
                   <a href="http://beian.miit.gov.cn" target="_blank">沪ICP备2025145173号-1</a>
                   <a href="http://www.beian.gov.cn" target="_blank">沪公网安备31010402335801号</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/encrypt')
def encrypt_page():
    """加密解密页面"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """加密文件接口 - 支持中文密码"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "未提供文件"}), 400

        file = request.files['file']
        password = request.form.get('password', '').strip()

        if not file or file.filename == '':
            return jsonify({"error": "无效的文件"}), 400

        if not password:
            return jsonify({"error": "密码不能为空"}), 400

        # 检查文件大小
        file.seek(0, 2)  # 移动到文件末尾
        file_size = file.tell()
        file.seek(0)  # 移回文件开头

        if file_size > Config.MAX_CONTENT_LENGTH:
            return jsonify({"error": f"文件过大，最大支持 {Config.MAX_CONTENT_LENGTH // 1024 // 1024}MB"}), 413

        # 生成唯一文件名
        file_id = generate_file_id()
        original_filename = secure_filename(file.filename)
        upload_path = os.path.join(Config.UPLOAD_FOLDER, f"{file_id}_{original_filename}")
        encrypted_path = os.path.join(Config.ENCRYPTED_FOLDER, f"{file_id}.ljrk")

        # 保存上传的文件
        file.save(upload_path)
        app.logger.info(f"文件上传成功: {original_filename}")

        # 加密文件
        result = encryptor.encrypt_file(upload_path, password, encrypted_path)

        # 删除上传的临时文件
        cleanup_file(upload_path)

        if not result['success']:
            # 如果加密失败，删除可能创建的加密文件
            cleanup_file(encrypted_path)
            return jsonify({"error": result['error']}), 500

        app.logger.info(f"文件加密完成: {original_filename}")

        return jsonify({
            "success": True,
            "file_id": file_id,
            "encrypted_name": f"{file_id}.ljrk",
            "original_name": original_filename
        })

    except Exception as e:
        app.logger.error(f"加密失败: {str(e)}")
        return jsonify({"error": f"加密失败: {str(e)}"}), 500


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """解密文件接口 - 支持中文密码"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "未提供文件"}), 400

        file = request.files['file']
        password = request.form.get('password', '').strip()

        if not file or file.filename == '':
            return jsonify({"error": "无效的文件"}), 400

        if not file.filename.endswith('.ljrk'):
            return jsonify({"error": "请选择有效的.ljrk文件"}), 400

        if not password:
            return jsonify({"error": "密码不能为空"}), 400

        # 检查文件大小
        file.seek(0, 2)  # 移动到文件末尾
        file_size = file.tell()
        file.seek(0)  # 移回文件开头

        if file_size > Config.MAX_CONTENT_LENGTH:
            return jsonify({"error": f"文件过大，最大支持 {Config.MAX_CONTENT_LENGTH // 1024 // 1024}MB"}), 413

        # 保存上传的加密文件
        file_id = generate_file_id()
        encrypted_path = os.path.join(Config.UPLOAD_FOLDER, f"{file_id}.ljrk")
        file.save(encrypted_path)
        app.logger.info(f"加密文件上传成功: {file.filename}")

        # 解密文件
        decrypted_path = os.path.join(Config.UPLOAD_FOLDER, f"decrypted_{file_id}")
        result = encryptor.decrypt_file(encrypted_path, password, decrypted_path)

        # 清理上传的加密文件
        cleanup_file(encrypted_path)

        if not result['success']:
            # 如果解密失败，删除可能创建的解密文件
            cleanup_file(decrypted_path)
            return jsonify({"error": result['error']}), 400

        # 使用解密器返回的最终路径
        final_path = result.get('final_path', decrypted_path)

        # 确定下载文件名
        download_name = f"decrypted_{file_id}{result.get('file_ext', '')}"

        # 检查文件是否存在且不为空
        if not os.path.exists(final_path) or os.path.getsize(final_path) == 0:
            app.logger.error(f"解密后的文件不存在: {final_path}")
            return jsonify({"error": "解密后的文件不存在"}), 500

        # 返回解密后的文件
        response = send_file(
            final_path,
            as_attachment=True,
            download_name=download_name
        )

        # 清理临时文件 - 确保在下载后删除
        @response.call_on_close
        def cleanup():
            cleanup_file(final_path)

        app.logger.info(f"文件解密成功: {file.filename} -> {download_name}")
        return response

    except Exception as e:
        app.logger.error(f"解密失败: {str(e)}")
        return jsonify({"error": f"解密失败: {str(e)}"}), 500


@app.route('/api/download/<file_id>')
def download_encrypted(file_id):
    """下载加密后的文件 - 确保下载后删除"""
    try:
        encrypted_path = os.path.join(Config.ENCRYPTED_FOLDER, f"{file_id}.ljrk")
        if not os.path.exists(encrypted_path):
            return jsonify({"error": "文件不存在"}), 404

        # 返回加密文件
        response = send_file(
            encrypted_path,
            as_attachment=True,
            download_name=f"{file_id}.ljrk"
        )

        # 清理临时文件 - 确保在下载后删除
        @response.call_on_close
        def cleanup():
            cleanup_file(encrypted_path)

        return response
    except Exception as e:
        app.logger.error(f"下载文件失败: {str(e)}")
        return jsonify({"error": f"下载失败: {str(e)}"}), 500


@app.route('/api/cleanup', methods=['POST'])
def api_cleanup():
    """手动清理所有临时文件"""
    try:
        # 清理uploads目录
        upload_files = os.listdir(Config.UPLOAD_FOLDER)
        for filename in upload_files:
            file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            cleanup_file(file_path)

        # 清理encrypted目录
        encrypted_files = os.listdir(Config.ENCRYPTED_FOLDER)
        for filename in encrypted_files:
            file_path = os.path.join(Config.ENCRYPTED_FOLDER, filename)
            cleanup_file(file_path)

        app.logger.info("手动清理完成")
        return jsonify({"success": True, "message": "清理完成"})
    except Exception as e:
        app.logger.error(f"清理失败: {str(e)}")
        return jsonify({"error": f"清理失败: {str(e)}"}), 500

@app.route('/manual')
def manual():
    return render_template('manual.html')


@app.route('/zgzxhomeworkmgr')
def homework_mgr():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>中国中学作业管理系统</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Microsoft YaHei', sans-serif; }
            body { background-color: #f5f7fa; color: #333; line-height: 1.6; }
            .container { width: 100%; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
            header { background: linear-gradient(135deg, #1a56db 0%, #0e2a5e 100%); color: white; padding: 1rem 0; position: sticky; top: 0; z-index: 100; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); }
            .navbar { display: flex; justify-content: space-between; align-items: center; }
            .logo { display: flex; align-items: center; gap: 10px; font-size: 1.8rem; font-weight: 700; }
            .nav-links { display: flex; gap: 2rem; }
            .nav-links a { color: white; text-decoration: none; font-weight: 500; transition: all 0.3s ease; padding: 0.5rem 1rem; border-radius: 4px; }
            .nav-links a:hover { background-color: rgba(255, 255, 255, 0.1); }
            .hero { background: linear-gradient(rgba(10, 25, 47, 0.8), rgba(10, 25, 47, 0.9)); color: white; padding: 4rem 0; text-align: center; }
            .hero h1 { font-size: 2.8rem; margin-bottom: 1.5rem; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3); }
            .hero p { font-size: 1.2rem; max-width: 800px; margin: 0 auto; opacity: 0.9; }
            .section { padding: 4rem 0; }
            .section-title { text-align: center; margin-bottom: 3rem; }
            .section-title h2 { font-size: 2.2rem; color: #0e2a5e; margin-bottom: 1rem; }
            .section-title p { color: #6b7280; max-width: 700px; margin: 0 auto; }
            .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; }
            .feature-card { background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05); transition: all 0.3s ease; padding: 2rem; text-align: center; }
            .feature-card:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); }
            .feature-icon { font-size: 3rem; margin-bottom: 1rem; color: #1a56db; }
            footer { background-color: #1e293b; color: white; padding: 3rem 0 1rem; }
            .footer-content { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 2rem; margin-bottom: 2rem; }
            .copyright { text-align: center; padding-top: 2rem; border-top: 1px solid rgba(255, 255, 255, 0.1); opacity: 0.7; }
            @media (max-width: 768px) {
                .nav-links { display: none; }
                .hero h1 { font-size: 2.2rem; }
            }
        </style>
    </head>
    <body>
        <header>
            <div class="container">
                <nav class="navbar">
                    <div class="logo">中国中学作业管理系统</div>
                    <div class="nav-links">
                        <a href="/">首页</a>
                        <a href="#features">功能特点</a>
                        <a href="#about">关于我们</a>
                    </div>
                </nav>
            </div>
        </header>

        <section class="hero">
            <div class="container">
                <h1>中国中学作业管理系统</h1>
                <p>专为中国中学设计的智能作业管理解决方案，提供多角色协作的作业管理平台</p>
            </div>
        </section>

        <section class="section" id="features">
            <div class="container">
                <div class="section-title">
                    <h2>系统功能特点</h2>
                    <p>全面的作业管理功能，满足不同用户需求</p>
                </div>
                <div class="features-grid">
                    <div class="feature-card">
                        <div class="feature-icon">👨‍🎓</div>
                        <h3>学生端</h3>
                        <p>学生可实时查看作业完成情况，了解自己的学习状态</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">👨‍🏫</div>
                        <h3>课代表教师端</h3>
                        <p>课代表和教师可快速记录和查询学生作业状态</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">⚙️</div>
                        <h3>管理端</h3>
                        <p>系统管理员管理用户权限和系统设置</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="section" id="about">
            <div class="container">
                <div class="section-title">
                    <h2>关于我们</h2>
                    <p>龙解软控 - 专业的软件开发团队</p>
                </div>
                <div class="feature-card">
                    <p>我们致力于为教育机构提供优质的软件解决方案，中国中学作业管理系统是我们专为中国中学设计的智能管理平台。</p>
                    <p>系统采用现代化的Web技术，支持多平台使用，操作简便，功能强大。</p>
                </div>
            </div>
        </section>

        <footer>
            <div class="container">
                <div class="footer-content">
                    <div>
                        <h3>中国中学作业管理系统</h3>
                        <p>专为中国中学设计的智能作业管理平台</p>
                    </div>
                    <div>
                        <h3>联系我们</h3>
                        <p>电话: 17717913079</p>
                        <p>邮箱: luiyixu@163.com</p>
                    </div>
                </div>
                <div class="copyright">
                    <p>&copy; 2025 龙解软控 版权所有</p>
                </div>
            </div>
        </footer>
    </body>
    </html>
    ''')


@app.route('/htgtmove')
def htgtmove():
    return render_template('htgtmove.html')


@app.route('/baidu_verify_codeva-e0TqNParQ7.html')
def baidu_verify_codeval():
    return render_template('baidu_verify_codeva-e0TqNParQ7.html')


@app.route('/BingSiteAuth.xml')
def BingSiteAuth():
    return render_template('BingSiteAuth.xml')


@app.route('/sfqd-club')
def sfqd_club():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>龙解软控-中国中学算法穹顶社</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
            }

            :root {
                --primary: #1a73e8;
                --primary-dark: #0d47a1;
                --secondary: #00bcd4;
                --dark: #0a192f;
                --light: #f8f9fa;
                --gray: #6c757d;
            }

            body {
                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                color: var(--light);
                line-height: 1.6;
                overflow-x: hidden;
                position: relative;
            }

            body::before {
                content: "";
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    radial-gradient(circle at 10% 20%, rgba(26, 115, 232, 0.1) 0%, transparent 20%),
                    radial-gradient(circle at 90% 80%, rgba(0, 188, 212, 0.1) 0%, transparent 20%);
                z-index: -1;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
            }

            header {
                padding: 30px 0;
                position: relative;
                z-index: 10;
            }

            .logo-container {
                display: flex;
                align-items: center;
                gap: 15px;
            }

            .logo {
                width: 70px;
                height: 70px;
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: 0 0 25px rgba(26, 115, 232, 0.5);
            }

            .logo i {
                font-size: 32px;
                color: white;
            }

            .logo-text {
                font-size: 28px;
                font-weight: 700;
                background: linear-gradient(to right, var(--primary), var(--secondary));
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                letter-spacing: 1px;
            }

            .tagline {
                font-size: 18px;
                color: var(--secondary);
                margin-top: 5px;
                font-weight: 300;
            }

            .hero {
                padding: 100px 0;
                text-align: center;
                position: relative;
            }

            .hero h1 {
                font-size: 3.5rem;
                margin-bottom: 20px;
                background: linear-gradient(to right, #fff, var(--secondary));
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                font-weight: 800;
                letter-spacing: 1px;
            }

            .hero p {
                font-size: 1.5rem;
                max-width: 800px;
                margin: 0 auto 40px;
                color: rgba(255, 255, 255, 0.9);
                font-weight: 300;
            }

            .hero-highlight {
                color: var(--secondary);
                font-weight: 600;
            }

            .hero::after {
                content: "";
                position: absolute;
                bottom: -60px;
                left: 50%;
                transform: translateX(-50%);
                width: 80%;
                height: 2px;
                background: linear-gradient(to right, transparent, var(--primary), transparent);
            }

            .about {
                padding: 100px 0;
            }

            .section-title {
                text-align: center;
                font-size: 2.5rem;
                margin-bottom: 60px;
                position: relative;
            }

            .section-title::after {
                content: "";
                position: absolute;
                bottom: -15px;
                left: 50%;
                transform: translateX(-50%);
                width: 100px;
                height: 4px;
                background: linear-gradient(to right, var(--primary), var(--secondary));
                border-radius: 2px;
            }

            .about-content {
                display: flex;
                gap: 50px;
                align-items: center;
            }

            .about-text {
                flex: 1;
            }

            .about-text h3 {
                font-size: 1.8rem;
                margin-bottom: 20px;
                color: var(--secondary);
            }

            .about-text p {
                margin-bottom: 20px;
                font-size: 1.1rem;
                color: rgba(255, 255, 255, 0.85);
            }

            .achievements {
                padding: 100px 0;
                background: rgba(10, 25, 47, 0.7);
                position: relative;
            }

            .achievements-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 30px;
                margin-top: 50px;
            }

            .achievement-card {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 15px;
                padding: 30px;
                transition: transform 0.3s, box-shadow 0.3s;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }

            .achievement-card:hover {
                transform: translateY(-10px);
                box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
                border-color: rgba(26, 115, 232, 0.3);
            }

            .achievement-icon {
                font-size: 40px;
                color: var(--secondary);
                margin-bottom: 20px;
            }

            .achievement-title {
                font-size: 1.5rem;
                margin-bottom: 15px;
                color: var(--secondary);
            }

            .achievement-list {
                list-style-type: none;
            }

            .achievement-list li {
                margin-bottom: 10px;
                padding-left: 25px;
                position: relative;
            }

            .achievement-list li::before {
                content: "✓";
                position: absolute;
                left: 0;
                color: var(--secondary);
                font-weight: bold;
            }

            .projects {
                padding: 100px 0;
            }

            .projects-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 30px;
                margin-top: 50px;
            }

            .project-card {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 15px;
                overflow: hidden;
                transition: transform 0.3s;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }

            .project-card:hover {
                transform: translateY(-10px);
            }

            .project-image {
                height: 200px;
                background: linear-gradient(135deg, rgba(26, 115, 232, 0.3), rgba(0, 188, 212, 0.3));
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .project-content {
                padding: 25px;
            }

            .project-title {
                font-size: 1.4rem;
                margin-bottom: 15px;
                color: var(--secondary);
            }

            .project-desc {
                color: rgba(255, 255, 255, 0.8);
            }

            .cta-section {
                padding: 100px 0;
                text-align: center;
            }

            .cta-title {
                font-size: 2.5rem;
                margin-bottom: 20px;
            }

            .cta-subtitle {
                font-size: 1.2rem;
                max-width: 700px;
                margin: 0 auto 50px;
                color: rgba(255, 255, 255, 0.8);
            }

            .buttons-container {
                display: flex;
                justify-content: center;
                gap: 30px;
                flex-wrap: wrap;
            }

            .btn {
                padding: 16px 40px;
                border-radius: 50px;
                font-size: 1.1rem;
                font-weight: 600;
                text-decoration: none;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 10px;
                min-width: 220px;
                justify-content: center;
            }

            .btn-primary {
                background: linear-gradient(to right, var(--primary), var(--primary-dark));
                color: white;
                box-shadow: 0 5px 20px rgba(26, 115, 232, 0.4);
            }

            .btn-primary:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 25px rgba(26, 115, 232, 0.6);
            }

            .btn-secondary {
                background: rgba(255, 255, 255, 0.1);
                color: white;
                border: 2px solid var(--secondary);
            }

            .btn-secondary:hover {
                background: rgba(0, 188, 212, 0.2);
                transform: translateY(-5px);
            }

            .btn-tertiary {
                background: linear-gradient(to right, #6a11cb, #2575fc);
                color: white;
                box-shadow: 0 5px 20px rgba(106, 17, 203, 0.4);
            }

            .btn-tertiary:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 25px rgba(106, 17, 203, 0.6);
            }

            footer {
                padding: 40px 0;
                text-align: center;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }

            .footer-links {
                display: flex;
                justify-content: center;
                gap: 30px;
                margin-bottom: 30px;
                flex-wrap: wrap;
            }

            .footer-link {
                color: rgba(255, 255, 255, 0.7);
                text-decoration: none;
                transition: color 0.3s;
            }

            .footer-link:hover {
                color: var(--secondary);
            }

            .icp {
                font-size: 0.9rem;
                color: rgba(255, 255, 255, 0.5);
            }

            .icp a {
                color: rgba(255, 255, 255, 0.7);
                text-decoration: none;
            }

            .icp a:hover {
                color: var(--secondary);
                text-decoration: underline;
            }

            @media (max-width: 992px) {
                .about-content {
                    flex-direction: column;
                }
                
                .hero h1 {
                    font-size: 2.8rem;
                }
                
                .hero p {
                    font-size: 1.2rem;
                }
            }

            @media (max-width: 768px) {
                .hero {
                    padding: 70px 0;
                }
                
                .hero h1 {
                    font-size: 2.3rem;
                }
                
                .section-title {
                    font-size: 2rem;
                }
                
                .buttons-container {
                    flex-direction: column;
                    align-items: center;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div class="logo-container">
                    <div class="logo">
                        <i class="fas fa-code"></i>
                    </div>
                    <div>
                        <div class="logo-text">算法穹顶社</div>
                        <div class="tagline">科技 · 创新 · 未来</div>
                    </div>
                </div>
            </header>

            <section class="hero">
                <h1>龙解软控-中国中学算法穹顶社</h1>
                <p>成立于<span class="hero-highlight">2025年9月</span>，是中国中学第一个科技类学生社团。我们旨在以<span class="hero-highlight">算法改变思维</span>，培养编程与工程人才，通过科技创新<span class="hero-highlight">解决现实问题</span>。</p>
            </section>

            <section class="about">
                <h2 class="section-title">社团简介</h2>
                <div class="about-content">
                    <div class="about-text">
                        <h3>科技引领未来，算法改变思维</h3>
                        <p>中国中学算法穹顶社成立于2025年9月，是中国中学历史上第一个专注于科技领域的学生社团。我们致力于通过算法和编程教育，改变学生对问题的思考方式，培养创新思维和解决问题的能力。</p>
                        <p>社团面向所有对编程、算法和工程项目感兴趣的同学开放，无论你是初学者还是有一定基础的技术爱好者，都能在这里找到成长的空间和展示的舞台。</p>
                        <p>我们定期组织技术培训、项目开发和竞赛准备活动，帮助社员提升技术水平，参加市级和区级的各类科技竞赛，并在实际项目中应用所学知识解决校园和社会的现实问题。</p>
                    </div>
                </div>
            </section>

            <section class="achievements">
                <h2 class="section-title">社团成就</h2>
                <div class="achievements-grid">
                    <div class="achievement-card">
                        <div class="achievement-icon">
                            <i class="fas fa-trophy"></i>
                        </div>
                        <h3 class="achievement-title">竞赛荣誉</h3>
                        <ul class="achievement-list">
                            <li>加拿大海狸计算机比赛（BCC）</li>
                            <li>加拿大计算机比赛（CCC）</li>
                            <li>第五届长三角人工智能奥林匹克挑战赛</li>
                        </ul>
                    </div>
                    
                    <div class="achievement-card">
                        <div class="achievement-icon">
                            <i class="fas fa-laptop-code"></i>
                        </div>
                        <h3 class="achievement-title">在研项目</h3>
                        <ul class="achievement-list">
                            <li>中国中学课后体育场馆预约系统</li>
                            <li>中国中学尔雅轩电影预约系统</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section class="projects">
                <h2 class="section-title">特色项目</h2>
                <div class="projects-grid">
                    <div class="project-card">
                        <div class="project-image">
                            <i class="fas fa-calendar-check fa-3x"></i>
                        </div>
                        <div class="project-content">
                            <h3 class="project-title">体育场馆预约系统</h3>
                            <p class="project-desc">基于Web的智能预约平台，方便学生课后预约使用学校体育场馆，优化资源分配。</p>
                        </div>
                    </div>
                    
                    <div class="project-card">
                        <div class="project-image">
                            <i class="fas fa-film fa-3x"></i>
                        </div>
                        <div class="project-content">
                            <h3 class="project-title">尔雅轩电影预约</h3>
                            <p class="project-desc">校园影院预约系统，提升校园文化体验。</p>
                        </div>
                    </div>
                    
                    <div class="project-card">
                        <div class="project-image">
                            <i class="fas fa-robot fa-3x"></i>
                        </div>
                        <div class="project-content">
                            <h3 class="project-title">中国中学作业管理系统</h3>
                            <p class="project-desc">数字化管理作业收发问题，方便高效。</p>
                        </div>
                    </div>
                </div>
            </section>

            <section class="cta-section">
                <h2 class="cta-title">加入我们，共创未来</h2>
                <p class="cta-subtitle">探索算法穹顶社的精彩活动，了解我们的课程安排，认识优秀的社团成员</p>
                
                <div class="buttons-container">
                    <a href="/sfqd-club/plan" class="btn btn-primary">
                        <i class="fas fa-calendar-alt"></i>
                        社团初期安排
                    </a>
                    
                    <a href="/sfqd-club/members" class="btn btn-secondary">
                        <i class="fas fa-users"></i>
                        社团成员
                    </a>
                    
                    <a href="#" class="btn btn-tertiary">
                        <i class="fas fa-book"></i>
                        社团课程
                    </a>
                </div>
            </section>
        </div>

        <footer>
            <div class="container">
                <div class="icp">
                    <a href="http://beian.miit.gov.cn" target="_blank">沪ICP备2025145173号</a>
                    <a href="http://www.beian.gov.cn" target="_blank">沪公网安备31010402335801号</a>
                </div>
            </div>
        </footer>
    </body>
    </html>
    ''')


@app.errorhandler(413)
def request_entity_too_large(error):
    """处理文件过大错误"""
    return jsonify({"error": f"文件过大，最大支持 {Config.MAX_CONTENT_LENGTH // 1024 // 1024}MB"}), 413


@app.errorhandler(500)
def internal_server_error(error):
    """处理服务器内部错误"""
    app.logger.error(f"服务器内部错误: {error}")
    return jsonify({"error": "服务器内部错误，请稍后再试"}), 500


# ==================== 启动代码 ====================
if __name__ == '__main__':
    print("=" * 50)
    print("支持中文密码的文件加密解密系统启动中...")
    print(f"服务器地址: http://{Config.HOST}:{Config.PORT}")
    print(f"文件大小限制: {Config.MAX_CONTENT_LENGTH // 1024 // 1024}MB")
    print(f"上传目录: {Config.UPLOAD_FOLDER}")
    print(f"加密文件目录: {Config.ENCRYPTED_FOLDER}")
    print("=" * 50)

    # 检查必要的目录
    for folder in [Config.UPLOAD_FOLDER, Config.ENCRYPTED_FOLDER, Config.LOG_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"创建目录: {folder}")

    # 使用 Waitress 生产服务器
    try:
        from waitress import serve

        print("使用 Waitress 生产服务器...")
        serve(
            app,
            host=Config.HOST,
            port=Config.PORT,
            threads=Config.WAITRESS_THREADS,
            channel_timeout=Config.WAITRESS_CHANNEL_TIMEOUT
        )
    except ImportError:
        print("Waitress 未安装，使用 Flask 开发服务器")
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG
        )
