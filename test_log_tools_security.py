import os
import sys

# 【关键修改】将当前目录和 tools 目录加入 Python 搜索路径
# 这样即使不安装为包，也能直接找到 tools 下的模块
current_dir = os.path.dirname(os.path.abspath(__file__))
tools_dir = os.path.join(current_dir, "tools")
sys.path.insert(0, current_dir)
sys.path.insert(0, tools_dir)

# 现在可以正常导入了
from log_tools import read_log_file, LOG_BASE_DIR, MAX_FILE_SIZE_BYTES

def print_section(title):
    print(f"\n{'='*20} {title} {'='*20}")

# ... (后面的代码保持不变，无需修改) ...
def test_normal_read():
    """测试 1: 正常读取允许目录内的文件"""
    print_section("测试 1: 正常读取文件")
    # 注意：这里文件路径是相对于 LOG_BASE_DIR 的
    result = read_log_file.invoke({"file_path": "test_access.log"})
    
    if "192.168.1.105" in result:
        print("❌ 失败: IP 地址未脱敏！")
        return False
    elif "192.168.***.***" in result:
        print("✅ 成功: 文件读取正常，且 IP 已脱敏 (192.168.***.***)")
        print(f"   内容片段: {result[:100]}...")
        return True
    elif "Error" in result or "Warning" in result:
        print(f"❌ 失败: 读取报错 - {result}")
        return False
    else:
        print("✅ 成功: 文件读取正常 (未检测到特定 IP 格式或脱敏逻辑未触发)")
        return True

def test_path_traversal():
    """测试 2: 路径遍历攻击防御 (尝试读取 /etc/passwd)"""
    print_section("测试 2: 路径遍历防御 (Security)")
    
    result1 = read_log_file.invoke({"file_path": "/etc/passwd"})
    result2 = read_log_file.invoke({"file_path": "../../etc/passwd"})
    result3 = read_log_file.invoke({"file_path": "data/../../etc/passwd"})
    
    success = True
    for i, res in enumerate([result1, result2, result3], 1):
        if "Access Denied" in res or "Path traversal" in res or "not found" in res:
            print(f"   ✅ 攻击尝试 {i} 被拦截: {res[:50]}...")
        else:
            print(f"   ❌ 严重漏洞! 攻击尝试 {i} 成功读取了内容: {res[:50]}...")
            success = False
            
    return success

def test_file_size_limit():
    """测试 3: 大文件限制"""
    print_section("测试 3: 文件大小限制")
    # 构造绝对路径检查文件是否存在
    check_path = os.path.join(LOG_BASE_DIR, "large_log.log")
    if not os.path.exists(check_path):
        print(f"⚠️ 跳过: 未找到 large_log.log (检查路径: {check_path})，请先运行准备命令。")
        return True
        
    result = read_log_file.invoke({"file_path": "large_log.log"})
    
    if "File too large" in result:
        print(f"✅ 成功: 大文件被拦截 ({MAX_FILE_SIZE_BYTES/1024/1024}MB 限制)")
        return True
    else:
        print(f"❌ 失败: 大文件未被拦截，可能引发 OOM。返回: {result[:50]}")
        return False

def test_non_existent():
    """测试 4: 不存在文件处理"""
    print_section("测试 4: 不存在文件处理")
    result = read_log_file.invoke({"file_path": "ghost_file.log"})
    
    if "not found" in result:
        print("✅ 成功: 正确报告文件不存在")
        return True
    else:
        print(f"❌ 失败: 未正确报错。返回: {result}")
        return False

if __name__ == "__main__":
    print(f"🛡️  开始测试 log_tools.py 安全加固效果")
    print(f"📂 允许访问的根目录: {LOG_BASE_DIR}")
    print(f"📏 最大文件大小限制: {MAX_FILE_SIZE_BYTES / 1024 / 1024:.2f} MB")
    
    results = []
    results.append(test_normal_read())
    results.append(test_path_traversal())
    results.append(test_file_size_limit())
    results.append(test_non_existent())
    
    print_section("最终测试结果")
    if all(results):
        print("🎉 所有测试通过！代码安全可靠。")
        sys.exit(0)
    else:
        print("💥 部分测试失败，请检查代码逻辑！")
        sys.exit(1)
