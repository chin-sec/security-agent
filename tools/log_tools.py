# tools/log_tools.py
import os

# 配置：最大允许读取的行数，防止大日志文件撑爆内存或消耗过多 Token
MAX_LINES_TO_READ = 500 

def read_log_file(filename: str) -> str:
    """
    安全地读取 data 目录下的日志文件。
    
    功能特点：
    1. 路径沙箱：强制限制在 data/ 目录下，防止路径遍历攻击。
    2. 智能路径：自动基于项目根目录解析，不受当前工作目录影响。
    3. 大文件保护：只读取前 N 行，避免内存溢出。
    4. 编码容错：优先 UTF-8，失败则尝试 latin-1。
    """
    
    # 1. 基础安全检查：文件名不能包含非法字符或上级目录引用
    if not filename or ".." in filename or filename.startswith("/"):
        return "❌ 错误：非法的文件名。为了安全，文件名不能包含 '..' 或绝对路径。"
    
    # 2. 构建安全路径
    # 获取当前文件 (log_tools.py) 所在的目录，向上找两级找到项目根目录 (假设结构: project/tools/log_tools.py)
    # 如果你的结构不同，请调整 os.path.dirname 的次数，或者直接指定绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir) # 假设 tools 在项目根目录下
    base_dir = os.path.join(project_root, "data")
    
    # 规范化路径并拼接
    safe_filename = os.path.basename(filename) # 再次确保只取文件名部分
    filepath = os.path.join(base_dir, safe_filename)
    
    # 3. 二次确认：确保最终路径真的在 data 目录下 (防绕过)
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)
    
    if not real_path.startswith(real_base):
        return "❌ 错误：安全拦截！试图访问 data 目录之外的文件。"

    # 4. 检查文件存在性
    if not os.path.exists(filepath):
        # 列出 data 目录下现有的文件，帮助用户调试
        try:
            available_files = os.listdir(base_dir)
            hint = f"当前 data 目录下有: {', '.join(available_files)}" if available_files else "当前 data 目录为空"
        except:
            hint = "无法列出 data 目录内容"
        return f"❌ 错误：找不到文件 '{safe_filename}'。\n💡 {hint}"
    
    # 5. 读取文件 (带行数限制和编码容错)
    try:
        lines = []
        # 尝试 UTF-8
        encoding_used = 'utf-8'
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if i >= MAX_LINES_TO_READ:
                        lines.append(f"\n... [已截断，仅显示前 {MAX_LINES_TO_READ} 行，文件过大]")
                        break
                    lines.append(line)
        except UnicodeDecodeError:
            # 如果 UTF-8 失败，尝试 latin-1 (几乎能读取所有二进制文本而不报错)
            encoding_used = 'latin-1'
            with open(filepath, 'r', encoding='latin-1') as f:
                for i, line in enumerate(f):
                    if i >= MAX_LINES_TO_READ:
                        lines.append(f"\n... [已截断，仅显示前 {MAX_LINES_TO_READ} 行，文件过大]")
                        break
                    lines.append(line)
        
        content = "".join(lines)
        warning = ""
        if len(lines) >= MAX_LINES_TO_READ:
            warning = f"\n⚠️ 注意：文件较大，已自动截断为前 {MAX_LINES_TO_READ} 行进行分析。如需分析更多内容，请手动拆分日志文件。\n\n"
            
        return f"{warning}(使用编码: {encoding_used})\n{content}"
        
    except PermissionError:
        return f"❌ 错误：没有权限读取文件 {filepath}。"
    except Exception as e:
        return f"❌ 读取文件时发生未知错误：{str(e)}"
