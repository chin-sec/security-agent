import os
import re
import logging
from typing import Optional
from langchain_core.tools import tool

# ================= 配置区域 =================
# 允许访问的日志根目录 (强烈建议通过环境变量设置，默认为当前目录下的 data 文件夹)
LOG_BASE_DIR = os.getenv("LOG_BASE_DIR", os.path.abspath("./data"))

# 单个文件最大读取限制 (5MB)，防止 OOM 或 Token 爆炸
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024 

# 是否启用敏感信息脱敏 (True: 开启, False: 关闭)
# 注意：如果业务强依赖真实 IP 进行封禁，可暂时关闭，但需确保传输链路加密且合规
ENABLE_SANITIZATION = True

# 初始化日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ================= 辅助函数 =================

def sanitize_sensitive_data(text: str) -> str:
    """
    对日志内容进行敏感信息脱敏处理。
    当前策略：
    1. IPv4 地址掩码：将后两段替换为 *** (例如 192.168.1.10 -> 192.168.***.***)
    2. 可扩展：添加邮箱、手机号等规则
    """
    if not text:
        return text
    
    # 正则匹配 IPv4
    ip_pattern = r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b'
    
    def mask_ip(match):
        # 保留前两段，掩码后两段
        return f"{match.group(1)}.{match.group(2)}.***.***"
    
    sanitized_text = re.sub(ip_pattern, mask_ip, text)
    
    # 这里可以添加更多脱敏规则，例如：
    # email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    # sanitized_text = re.sub(email_pattern, '[EMAIL_REDACTED]', sanitized_text)
    
    return sanitized_text

def validate_file_path(file_path: str) -> tuple[bool, str]:
    """
    严格校验文件路径安全性。
    返回: (is_valid, message_or_full_path)
    """
    if not file_path:
        return False, "Error: File path is empty."

    # 1. 规范化路径 (解决 ../../ 问题)
    # 将用户输入的路径拼接到允许的根目录下
    # 如果用户输入的是绝对路径，os.path.join 会忽略 LOG_BASE_DIR，所以必须先判断
    if os.path.isabs(file_path):
        # 如果用户传了绝对路径，检查它是否在允许目录内
        normalized_input = os.path.normpath(file_path)
        if not normalized_input.startswith(os.path.abspath(LOG_BASE_DIR)):
            return False, "Error: Access Denied. Absolute path outside allowed directory."
        safe_path = normalized_input
    else:
        # 相对路径，强制拼接到 LOG_BASE_DIR
        safe_path = os.path.normpath(os.path.join(LOG_BASE_DIR, file_path))

    # 2. 二次确认：确保解析后的绝对路径依然在允许目录内 (防御 symlink 攻击)
    abs_safe_path = os.path.abspath(safe_path)
    abs_allowed_root = os.path.abspath(LOG_BASE_DIR)
    
    if not abs_safe_path.startswith(abs_allowed_root):
        logger.warning(f"Path traversal attempt detected: {file_path} -> {abs_safe_path}")
        return False, "Error: Access Denied. Path traversal detected."

    # 3. 检查文件是否存在
    if not os.path.exists(abs_safe_path):
        return False, f"Error: File not found at {abs_safe_path}"

    # 4. 检查是否是文件 (防止读取目录)
    if not os.path.isfile(abs_safe_path):
        return False, "Error: Target is not a regular file."

    # 5. 检查文件大小
    file_size = os.path.getsize(abs_safe_path)
    if file_size > MAX_FILE_SIZE_BYTES:
        return False, f"Error: File too large ({file_size / 1024 / 1024:.2f}MB). Max limit is {MAX_FILE_SIZE_BYTES / 1024 / 1024}MB. Please use streaming analysis."

    return True, abs_safe_path

# ================= LangChain 工具定义 =================

@tool
def read_log_file(file_path: str) -> str:
    """
    读取指定路径的日志文件内容用于安全分析。
    
    Args:
        file_path: 日志文件的路径 (可以是相对于 LOG_BASE_DIR 的相对路径)。
                   严禁传入系统绝对路径如 /etc/passwd。
    
    Returns:
        文件内容字符串。如果发生错误（如文件不存在、权限拒绝、文件过大），返回错误信息字符串。
        注意：出于安全考虑，返回内容中的敏感 IP 地址可能已被脱敏。
    """
    logger.info(f"Attempting to read log file: {file_path}")
    
    # 1. 路径安全校验
    is_valid, result = validate_file_path(file_path)
    if not is_valid:
        logger.warning(f"Security check failed for {file_path}: {result}")
        return result
    
    safe_abs_path = result
    
    try:
        # 2. 读取文件
        # 使用 utf-8 编码，遇到错误字符忽略，防止编码问题崩溃
        with open(safe_abs_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        if not content:
            return "Warning: The log file is empty."
        
        # 3. 敏感数据脱敏 (如果开启)
        if ENABLE_SANITIZATION:
            logger.debug("Sanitizing sensitive data in log content...")
            content = sanitize_sensitive_data(content)
        
        logger.info(f"Successfully read and processed file: {safe_abs_path} (Size: {len(content)} chars)")
        return content
        
    except PermissionError:
        logger.error(f"Permission denied: {safe_abs_path}")
        return "Error: Permission denied to read this file."
    except Exception as e:
        logger.error(f"Unexpected error reading file {safe_abs_path}: {str(e)}")
        return f"Error: Failed to read file due to unexpected issue: {str(e)}"

# 导出工具列表，方便其他模块导入
__all__ = ["read_log_file"]
