import os

def read_log_file(filepath: str, max_lines: int = 500) -> str:
    """
    读取日志文件内容。
    为防止上下文过长，默认只读取最后 max_lines 行。
    """
    if not os.path.exists(filepath):
        return f"错误：文件 {filepath} 不存在。请检查路径是否正确。"
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # 如果文件过大，只取最后部分
        if len(lines) > max_lines:
            content = "".join(lines[-max_lines:])
            return f"(文件较大，仅显示最后 {max_lines} 行):\n{content}"
        
        return "".join(lines)
    except PermissionError:
        return f"错误：没有权限读取文件 {filepath}。"
    except Exception as e:
        return f"错误：读取文件时发生异常 - {str(e)}"
