import os
from agents.log_agent import analyze_log_content

if __name__ == "__main__":
    print("正在启动 AI 安全日志分析助手...\n")
    
    log_file_path = "data/auth.log"
    
    if not os.path.exists(log_file_path):
        print(f"❌ 错误：找不到文件 {log_file_path}")
        exit(1)
        
    # --- 智能预处理逻辑 ---
    target_lines = []
    keywords = ["Failed", "Invalid", "error", "refused", "break-in", "Bad protocol"]
    
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()
            
        print(f"📄 原始日志行数：{len(all_lines)}")
        
        # 1. 过滤：只保留疑似攻击的行 (大幅减少 Token)
        for line in all_lines:
            if any(k in line for k in keywords):
                target_lines.append(line)
        
        print(f"🔍 筛选后疑似攻击行数：{len(target_lines)}")
        
        # 2. 截断：如果还是太多，只取最后 600 条 (聚焦最近攻击)
        MAX_LINES = 600
        if len(target_lines) > MAX_LINES:
            target_lines = target_lines[-MAX_LINES:]
            print(f"✂️  检测到攻击记录过多，已自动截取【最近 {MAX_LINES} 条】进行分析。")
        else:
            print(f"ℹ️  攻击记录适中，将分析全部 {len(target_lines)} 条记录。")
            
        # 组合内容
        content = "".join(target_lines)
        
        if not content:
            print("⚠️  未检测到明显的失败登录或错误日志。将尝试分析全文最后 200 行。")
            content = "".join(all_lines[-200:])

    except Exception as e:
        print(f"❌ 读取文件失败：{e}")
        exit(1)

    # --- 构建提示词 ---
    query = (
        "你是一名资深的安全分析师。请分析以下经过预处理的 SSH 登录日志（已过滤正常登录，仅含异常记录）。\n\n"
        "【日志内容】：\n"
        f"{content}\n\n"
        "【输出要求】：\n"
        "1. **严禁**输出任何思考过程、中间步骤、'Thought'、'Action' 等字样。\n"
        "2. **直接**输出一份结构化的《安全分析报告》。\n"
        "3. 报告必须包含以下章节：\n"
        "   - 🛑 攻击摘要 (简述攻击类型、时间跨度)\n"
        "   - 📊 攻击 IP 统计 (列出 Top 5 恶意 IP 及其尝试次数，格式：IP - 次数)\n"
        "   - 🎯 受影响账户 (哪些用户被爆破)\n"
        "   - ⚠️ 风险等级 (高/中/低)\n"
        "   - 🛡️ 防御建议 (针对性的具体 Linux 命令，如 fail2ban 配置或 iptables 规则)\n"
    )
    
    try:
        print("\n🚀 正在调用 AI 进行深度分析...\n")
        result = analyze_log_content(query)
        print("\n" + "="*40)
        print(result)
        print("="*40)
    except Exception as e:
        print(f"\n系统执行出错：{e}")
