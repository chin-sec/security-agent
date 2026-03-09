from agents.log_agent import run_agent

if __name__ == "__main__":
    # 1. 定义查询指令
    # 确保这个路径下的文件真实存在，或者测试一个不存在的路径看 Agent 反应
    query = "请读取 data/auth.log 文件，分析其中的异常登录行为，并生成安全报告。"
    
    print("正在启动 AI 安全日志分析助手...")
    try:
        # 2. 调用 agent 执行任务
        result = run_agent(query)
        
        # 3. 输出结果
        print("\n=== 安全分析报告 ===")
        print(result)
        
    except Exception as e:
        # 捕获 LLM 调用失败、网络错误等系统性异常
        print(f"\n系统执行出错：{type(e).__name__} - {e}")
        print("提示：请检查 DASHSCOPE_API_KEY 是否正确配置，以及网络连接是否正常。")
