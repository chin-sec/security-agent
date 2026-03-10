import os
from agents.log_agent import analyze_log_content

if __name__ == "__main__":
    print("正在启动 AI 安全日志分析助手...\n")
    
    log_file_path = "data/auth.log"
    
    # 1. 直接在 Python 层读取文件 (避免 Agent 工具调用的路径解析错误)
    if not os.path.exists(log_file_path):
        print(f"❌ 错误：找不到文件 {log_file_path}")
        exit(1)
        
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # 为了防止 Token 超限，只读取最后 2000 行 (通常攻击都在最近)
            # 如果文件很小，则全部读取
            lines = f.readlines()
            if len(lines) > 2000:
                content = "".join(lines[-2000:])
                print(f"ℹ️  文件过大 ({len(lines)} 行)，已自动截取最后 2000 行进行分析。")
            else:
                content = "".join(lines)
                print(f"ℹ️  已加载日志文件 ({len(lines)} 行)。")
    except Exception as e:
        print(f"❌ 读取文件失败：{e}")
        exit(1)

    # 2. 构建提示词
    query = (
        "你是一名资深的安全分析师。请分析以下 SSH 登录日志内容，识别异常行为和攻击来源。\n\n"
        "【日志内容】：\n"
        f"{content}\n\n"
        "【输出要求】：\n"
        "1. **严禁**输出任何思考过程、中间步骤、'Thought'、'Action' 等字样。\n"
        "2. **直接**输出一份结构化的《安全分析报告》。\n"
        "3. 报告必须包含以下章节：\n"
        "   - 🛑 攻击摘要 (简述发生了什么)\n"
        "   - 📊 攻击 IP 统计 (列出 Top 5 恶意 IP 及其尝试次数)\n"
        "   - 🎯 受影响账户 (哪些用户被爆破)\n"
        "   - ⚠️ 风险等级 (高/中/低)\n"
        "   - 🛡️ 防御建议 (针对性的具体命令或配置)\n"
    )
    
    try:
        # 调用新的分析函数 (不再需要 verbose，因为不需要工具交互)
        result = analyze_log_content(query)
        print("\n" + "="*30)
        print(result)
        print("="*30)
    except Exception as e:
        print(f"\n系统执行出错：{e}")
