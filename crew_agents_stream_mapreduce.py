import os
import warnings

# 1. 设置环境变量 (双重保险)
os.environ["CREWAI_TRACING_ENABLED"] = "false"
os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "" 
os.environ["CREWAI_TELEMETRY_DISABLED"] = "true"

# 2. 在导入 crewai 之前，尝试直接禁用其内部追踪器
try:
    # 预加载配置，防止 crewai 初始化时弹出提示
    from crewai.telemetry import Telemetry
    # 如果类存在，尝试将其方法空转 (针对新版本 crewai)
    def noop(*args, **kwargs): pass
    if hasattr(Telemetry, 'start_tracer'):
        Telemetry.start_tracer = noop
    if hasattr(Telemetry, 'log_crew_execution'):
        Telemetry.log_crew_execution = noop
except Exception:
    pass # 如果版本不同导致失败，忽略错误，继续执行

# 3. 过滤特定的警告信息 (针对那个 Tracing Status 框)
warnings.filterwarnings("ignore", message=".*Tracing.*")
warnings.filterwarnings("ignore", message=".*telemetry.*")

# ================= 1. 正常导入其他库 =================
import json
import math
from pathlib import Path
from typing import Type, Any, List, Dict, Optional
from collections import Counter
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import re
import time

# ================= 1. 配置与环境变量 =================

api_key = os.getenv("DASHSCOPE_API_KEY")
if not api_key:
    raise ValueError("❌ 错误: 环境变量 DASHSCOPE_API_KEY 未设置！")

MODEL_NAME = "qwen-max" 
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

os.environ["OPENAI_API_KEY"] = api_key
os.environ["OPENAI_BASE_URL"] = BASE_URL
os.environ["CREWAI_TRACING_ENABLED"] = "false"

LOG_BASE_DIR = os.getenv("LOG_BASE_DIR", os.getcwd())
print(f"✅ LLM 配置已准备就绪 (模型: {MODEL_NAME})")
print(f"📂 日志基准目录设置为: {LOG_BASE_DIR}")

# ================= 2. 数据模型定义 =================

class ReadLogInput(BaseModel):
    file_path: str = Field(description="日志文件的路径")

class RetrieveKnowledgeInput(BaseModel):
    query: str = Field(description="要检索的安全知识主题")

# ================= 3. 工具封装 (核心升级：流式 Map-Reduce) =================

class StreamLogAnalyzerTool(BaseTool):
    name: str = "stream_analyze_log"
    description: str = """
    流式分析大型日志文件。
    1. 自动将文件分块 (每块 3000 行)。
    2. 对每个块进行本地关键词过滤和 IP 统计 (Map)。
    3. 合并所有块的统计结果 (Reduce)。
    4. 返回全局 Top IP 统计和最具代表性的 50 条日志样本。
    适用于 GB 级大文件，不会内存溢出。
    """
    args_schema: Type[BaseModel] = ReadLogInput
    
    def _run(self, file_path: str) -> str:
        input_path = Path(file_path)
        if input_path.is_absolute():
            final_path = input_path
        else:
            final_path = Path(LOG_BASE_DIR) / input_path
        
        final_path = final_path.resolve()
        
        if not final_path.exists():
            raise FileNotFoundError(f"文件未找到: '{final_path}'")
        
        print(f"🔄 启动流式分析引擎: {final_path} ...")
        
        # 全局聚合变量 (Reduce 阶段用)
        global_ip_counter = Counter()
        global_security_events = 0
        total_lines_scanned = 0
        representative_samples = [] # 存储最具代表性的样本
        
        # 配置
        CHUNK_SIZE = 3000
        MAX_SAMPLES = 50
        keywords = ['Failed password', 'Invalid user', 'Accepted password', 'error', 'authentication failure', 'POSSIBLE BREAK-IN']
        
        # 临时变量用于当前块的处理
        current_chunk_lines = []
        chunk_id = 0
        
        def process_chunk(lines: List[str], chunk_id: int):
            nonlocal global_ip_counter, global_security_events, representative_samples
            local_counter = Counter()
            local_events = 0
            
            for line in lines:
                if any(kw in line for kw in keywords):
                    local_events += 1
                    global_security_events += 1
                    
                    # 提取 IP
                    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        local_counter[ip_match.group(1)] += 1
                    
                    # 采样逻辑：优先保留前几个，然后随机替换或保留高严重度的
                    # 这里简化：只取前 MAX_SAMPLES 个遇到的安全行，或者可以优化为保留不同 IP 的样本
                    if len(representative_samples) < MAX_SAMPLES:
                        representative_samples.append(line.strip())
            
            # 合并本地 IP 计数到全局
            global_ip_counter.update(local_counter)
            print(f"   - 块 {chunk_id} 处理完成: 发现 {local_events} 个安全事件")

        try:
            with open(final_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_lines_scanned += 1
                    current_chunk_lines.append(line)
                    
                    if len(current_chunk_lines) >= CHUNK_SIZE:
                        chunk_id += 1
                        process_chunk(current_chunk_lines, chunk_id)
                        current_chunk_lines = [] # 释放内存
            
            # 处理最后一块
            if current_chunk_lines:
                chunk_id += 1
                process_chunk(current_chunk_lines, chunk_id)
            
            print(f"✅ 流式扫描完成: 总行数 {total_lines_scanned}, 安全事件 {global_security_events}")
            
            # 构建最终报告 (Reduce 输出)
            top_ips = global_ip_counter.most_common(10) # 取 Top 10
            
            report_lines = [
                f"=== 大规模日志流式分析报告 (Map-Reduce) ===",
                f"文件路径: {final_path}",
                f"总扫描行数: {total_lines_scanned:,}",
                f"识别到的安全事件总数: {global_security_events:,}",
                f"处理块数: {chunk_id}",
                f"",
                f"=== 全局 Top 10 攻击源 IP (聚合统计) ==="
            ]
            
            for ip, count in top_ips:
                report_lines.append(f"- {ip}: {count} 次尝试")
            
            if not top_ips:
                report_lines.append("- 未发现明显的 IP 攻击模式")
                
            report_lines.append("")
            report_lines.append("=== 关键日志样本 (代表性事件) ===")
            report_lines.extend(representative_samples)
            
            if global_security_events > MAX_SAMPLES:
                report_lines.append(f"... (共 {global_security_events} 个事件，此处仅展示 {MAX_SAMPLES} 条样本)")
            
            return "\n".join(report_lines)

        except Exception as e:
            raise RuntimeError(f"流式分析失败: {str(e)}")

# 兼容旧版工具名引用 (如果其他地方有引用)
ReadLogTool = StreamLogAnalyzerTool

class RetrieveKnowledgeTool(BaseTool):
    name: str = "retrieve_knowledge"
    description: str = "检索本地安全知识库。"
    args_schema: Type[BaseModel] = RetrieveKnowledgeInput
    
    def _run(self, query: str) -> str:
        # 模拟检索，实际应调用你的 retrieval_tools
        return f"关于 '{query}' 的安全知识：建议检查防火墙规则，启用 Fail2Ban，并定期更新系统补丁。"

log_tool = StreamLogAnalyzerTool()
knowledge_tool = RetrieveKnowledgeTool()

# ================= 4. Agent 定义 (保持与你原版一致) =================

log_collector = Agent(
    role="高级日志采集与预处理专家",
    goal="使用流式工具读取日志文件，过滤噪音，提取关键安全事件，并统计全局攻击 IP。",
    backstory="""你是一名高效的数据工程师。
    你使用的是工业级流式分析工具，可以处理 GB 级文件。
    你的任务是输出包含【全局统计数据】和【代表性样本】的精简报告。""",
    tools=[log_tool],
    llm=MODEL_NAME,
    allow_delegation=False,
    verbose=True
)

security_analyst = Agent(
    role="资深网络安全分析师",
    goal="基于预处理后的统计数据和样本日志，撰写深度安全分析报告。",
    backstory="""你拥有 10 年经验。
    你不需要重新数 IP 次数（工具已经完成了全量统计），你需要做的是：
    1. 解读 Top IP 的攻击意图。
    2. 分析样本日志中的攻击手法。
    3. 结合知识库给出防御建议。
    4. 生成专业的《安全分析报告》。""",
    tools=[knowledge_tool],
    llm=MODEL_NAME,
    allow_delegation=False,
    verbose=True
)

# ================= 5. 任务定义 (保持与你原版一致) =================

task_collect = Task(
    description="""
    使用 stream_analyze_log 工具处理路径为 {log_path} 的文件。
    输出要求：直接输出工具返回的全局精简报告（包含统计数据和样本）。
    """,
    expected_output="包含全局 IP 统计和日志样本的精简报告字符串",
    agent=log_collector
)

task_analyze = Task(
    description="""
    基于上一步提供的【全局精简报告】进行分析：
    1. **威胁概览**：总结攻击规模和主要特征。
    2. **攻击源分析**：详细解读 Top 3 IP 的行为模式。
    3. **防御建议**：
       - 针对 Top IP 的具体 iptables 命令。
       - 长期加固建议（如 Fail2Ban 配置思路）。
    
    注意：直接使用报告中提供的全局统计数据。
    """,
    expected_output="一份结构清晰、专业且基于真实数据的 Markdown 格式《安全分析报告》",
    agent=security_analyst,
    context=[task_collect]
)

# ================= 6. Crew 组建 (保持与你原版一致) =================

crew = Crew(
    agents=[log_collector, security_analyst],
    tasks=[task_collect, task_analyze],
    process=Process.sequential,
    verbose=True,
    memory=False,
    cache=False
)

if __name__ == "__main__":
    import datetime
    
    print("🚀 启动多 Agent 协作安全分析系统 (流式 Map-Reduce 增强版)...")
    inputs = {"log_path": "data/auth.log"}
    
    os.makedirs("reports", exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"reports/security_report_stream_{timestamp}.txt"
    
    try:
        result = crew.kickoff(inputs=inputs)
        
        final_output = "\n" + "="*60 + "\n"
        final_output += "           🛡️  多 Agent 协作分析报告 (流式增强版) 🛡️\n"
        final_output += "="*60 + "\n"
        final_output += str(result) + "\n"
        final_output += "="*60 + "\n"
        
        print(final_output)
        print("✅ 协作完成。")
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(final_output)
        
        print(f"💾 报告已自动保存至: {output_file}")
        
    except Exception as e:
        error_msg = f"\n❌ 执行错误：{e}"
        print(error_msg)
        with open("reports/error_log.txt", "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {error_msg}\n")
        import traceback
        traceback.print_exc()
