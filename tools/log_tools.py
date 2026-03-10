import os
from typing import Optional, Type
from langchain_core.tools import BaseTool, tool  # 【关键】必须从 langchain_core 导入

# --- 方案 A: 使用 @tool 装饰器 (推荐，最简洁) ---
@tool
def read_log_file(file_path: str) -> str:
    """
    读取指定路径的日志文件内容。
    
    参数:
        file_path (str): 日志文件的绝对或相对路径，例如 'data/auth.log'。
    
    返回:
        str: 文件的完整文本内容。如果文件不存在或读取失败，返回错误信息字符串。
    """
    try:
        if not os.path.exists(file_path):
            return f"Error: File not found at {file_path}"
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        if not content:
            return "Warning: File is empty."
            
        return content
    except Exception as e:
        return f"Error reading file: {str(e)}"

# --- 方案 B: 如果你需要更复杂的自定义工具类 (备选，目前不需要) ---
# class CustomReadLogTool(BaseTool):
#     name: str = "read_log_file"
#     description: str = "读取指定路径的日志文件内容。参数 file_path 是文件路径。"
#     
#     def _run(self, file_path: str) -> str:
#         return read_log_file.invoke({"file_path": file_path})
#     
#     def _arun(self, file_path: str):
#         raise NotImplementedError("Async not supported")

# 导出工具，方便 crew_agents.py 导入
__all__ = ["read_log_file"]
