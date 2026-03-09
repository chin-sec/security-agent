from agents.log_agent import run_agent

if __name__ == "__main__":
    print("正在启动 AI 安全日志分析助手...")
    query = "请读取 data/auth.log 文件，分析其中的异常登录行为，并总结攻击来源 IP。"
    
    try:
        result = run_agent(query)
        print("\n=== 安全分析报告 ===")
        print(result)
    except Exception as e:
        print(f"\n系统执行出错：{e}")
