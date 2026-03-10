# crew_agents_stream_mapreduce.py
import os
from pathlib import Path
from typing import Type, Any, List, Dict
from collections import Counter
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import re
import warnings

# --- 强制静默设置 (放在最前) ---
os.environ["CREWAI_TRACING_ENABLED"] = "false"
os.environ["CREWAI_TELEMETRY_DISABLED"] = "true"
warnings.filterwarnings("ignore", message=".*Tracing.*")
warnings.filterwarnings("ignore", message=".*telemetry.*")

# --- 配置 ---
MODEL_NAME = os.getenv("MODEL_NAME", "qwen-max")
BASE_URL = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
API_KEY = os.getenv("DASHSCOPE_API_KEY")

if not API_KEY:
    # 在 Docker 中可能通过 env 文件注入，如果这里没有，先不报错，等到 kickoff 时再报
    pass

os.environ["OPENAI_API_KEY"] = API_KEY or "dummy"
os.environ["OPENAI_BASE_URL"] = BASE_URL

LOG_BASE_DIR = os.getenv("LOG_BASE_DIR", "/app/data") # Docker 中默认路径

# --- 数据模型 ---
class ReadLogInput(BaseModel):
    file_path: str = Field(description="日志文件的路径")

# --- 工具定义 (流式分析核心) ---
class StreamLogAnalyzerTool(BaseTool):
    name: str = "stream_analyze_log"
    description: str = "流式分析大型日志文件，返回全局统计和样本。"
    args_schema: Type[BaseModel] = ReadLogInput
    
    def _run(self, file_path: str) -> str:
        # 处理路径
        input_path = Path(file_path)
        if not input_path.is_absolute():
            input_path = Path(LOG_BASE_DIR) / input_path
        
        if not input_path.exists():
            raise FileNotFoundError(f"文件未找到: {input_path}")
        
        print(f"🔄 开始流式分析: {input_path}")
        
        global_ip_counter = Counter()
        global_security_events = 0
        total_lines = 0
        samples = []
        CHUNK_SIZE = 3000
        MAX_SAMPLES = 50
        keywords = ['Failed password', 'Invalid user', 'error', 'authentication failure']
        
        current_chunk = []
        
        def process_chunk(lines):
            nonlocal global_ip_counter, global_security_events, samples
            for line in lines:
                if any(kw in line for kw in keywords):
                    global_security_events += 1
                    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        global_ip_counter[ip_match.group(1)] += 1
                    if len(samples) < MAX_SAMPLES:
                        samples.append(line.strip())
        
        try:
            with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_lines += 1
                    current_chunk.append(line)
                    if len(current_chunk) >= CHUNK_SIZE:
                        process_chunk(current_chunk)
                        current_chunk = []
                if current_chunk:
                    process_chunk(current_chunk)
            
            # 构建结果
            res = [
                f"=== 日志分析报告 ===",
                f"文件: {input_path}",
                f"总行数: {total_lines:,}",
                f"安全事件: {global_security_events:,}",
                f"\n=== Top 5 攻击 IP ==="
            ]
            for ip, count in global_ip_counter.most_common(5):
                res.append(f"{ip}: {count} 次")
            
            res.append(f"\n=== 样本日志 (Top {len(samples)}) ===")
            res.extend(samples)
            return "\n".join(res)
        except Exception as e:
            return f"分析出错: {str(e)}"

# --- Agent 定义 ---
def create_crew():
    """工厂函数：创建并返回 Crew 实例，避免导入时立即初始化"""
    if not os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY") == "dummy":
        raise ValueError("缺少 DASHSCOPE_API_KEY 环境变量")

    log_tool = StreamLogAnalyzerTool()
    
    agent_collector = Agent(
        role="日志分析专家",
        goal="提取关键安全指标",
        backstory="你擅长处理海量日志。",
        tools=[log_tool],
        llm=MODEL_NAME,
        verbose=False
    )
    
    agent_analyst = Agent(
        role="安全架构师",
        goal="生成防御报告",
        backstory="你基于数据提供专业建议。",
        llm=MODEL_NAME,
        verbose=False
    )
    
    task_collect = Task(
        description="使用 stream_analyze_log 工具分析 {log_path}。",
        expected_output="统计数据和样本",
        agent=agent_collector
    )
    
    task_analyze = Task(
        description="基于上一步数据，生成 Markdown 格式的安全报告，包含 iptables 命令。",
        expected_output="Markdown 报告",
        agent=agent_analyst,
        context=[task_collect]
    )
    
    return Crew(
        agents=[agent_collector, agent_analyst],
        tasks=[task_collect, task_analyze],
        process=Process.sequential,
        verbose=False,
        memory=False,
        cache=False
    )

# 只有直接运行此脚本时才执行
if __name__ == "__main__":
    import datetime
    print("⚠️ 此脚本主要用于被 api.py 导入。如需独立运行，请确保配置了环境变量。")
    # 这里可以保留简单的测试逻辑，或者留空
