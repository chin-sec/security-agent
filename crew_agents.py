import os
from pathlib import Path
from typing import Type, Any, List, Dict
from collections import Counter
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import re

# ================= 1. 配置与环境变量 =================

api_key = os.getenv("DASHSCOPE_API_KEY")
if not api_key:
    raise ValueError("❌ 错误: 环境变量 DASHSCOPE_API_KEY 未设置！")

MODEL_NAME = "qwen-max" 
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

os.environ["OPENAI_API_KEY"] = api_key
os.environ["OPENAI_BASE_URL"] = BASE_URL

LOG_BASE_DIR = os.getenv("LOG_BASE_DIR", os.getcwd())
print(f"✅ LLM 配置已准备就绪 (模型: {MODEL_NAME})")
print(f"📂 日志基准目录设置为: {LOG_BASE_DIR}")

# ================= 2. 数据模型定义 (必须在工具类之前定义) =================

class ReadLogInput(BaseModel):
    file_path: str = Field(description="日志文件的路径")

class RetrieveKnowledgeInput(BaseModel):
    query: str = Field(description="要检索的安全知识主题")

# ================= 3. 工具封装 (智能过滤与统计版) =================

from tools.log_tools import read_log_file
from tools.retrieval_tools import retrieve_knowledge

class ReadLogTool(BaseTool):
    name: str = "read_log_file"
    description: str = "读取日志文件，自动过滤无关行，提取安全相关事件，并统计 Top 攻击 IP。返回精简后的分析报告数据。"
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
        if not final_path.is_file():
            raise IsADirectoryError(f"路径是一个目录: '{final_path}'")
        if not os.access(final_path, os.R_OK):
            raise PermissionError(f"无权限读取: '{final_path}'")

        print(f"🔍 正在智能分析文件: {final_path} (大小: {final_path.stat().st_size} bytes)")
        
        # 【核心优化】直接在工具层进行预处理
        relevant_lines = []
        ip_counter = Counter()
        total_lines = 0
        security_events = 0
        
        # 定义关注的安全关键词
        keywords = ['Failed password', 'Invalid user', 'Accepted password', 'error', 'authentication failure']
        
        try:
            with open(final_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_lines += 1
                    # 简单的启发式过滤：只保留包含安全关键词的行
                    if any(kw in line for kw in keywords):
                        relevant_lines.append(line.strip())
                        security_events += 1
                        
                        # 提取 IP 地址 (简单的正则)
                        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip_counter[ip_match.group(1)] += 1
                    
                    # 限制最大处理行数，防止内存溢出
                    if len(relevant_lines) >= 2000:
                        break
            
            # 构建结构化摘要
            top_ips = ip_counter.most_common(5)
            
            summary_report = [
                f"=== 日志文件智能预处理报告 ===",
                f"文件路径: {final_path}",
                f"总扫描行数: {total_lines}",
                f"安全相关事件行数: {security_events} (已截取前 2000 条供分析)",
                f"",
                f"=== Top 5 攻击源 IP 统计 (工具层预计算) ==="
            ]
            
            for ip, count in top_ips:
                summary_report.append(f"- {ip}: {count} 次尝试")
            
            if not top_ips:
                summary_report.append("- 未发现明显的 IP 攻击模式")
                
            summary_report.append("")
            summary_report.append("=== 关键日志片段 (样本) ===")
            # 只返回前 50 行样本
            sample_lines = relevant_lines[:50]
            summary_report.extend(sample_lines)
            
            if len(relevant_lines) > 50:
                summary_report.append(f"... (还有 {len(relevant_lines) - 50} 条相关日志已省略，请参考上方的 IP 统计数据)")
            
            return "\n".join(summary_report)

        except Exception as e:
            raise RuntimeError(f"处理文件时出错: {str(e)}")

class RetrieveKnowledgeTool(BaseTool):
    name: str = "retrieve_knowledge"
    description: str = "检索本地安全知识库。"
    args_schema: Type[BaseModel] = RetrieveKnowledgeInput  # 现在可以安全引用了
    
    def _run(self, query: str) -> str:
        return retrieve_knowledge.invoke({"query": query})

log_tool = ReadLogTool()
knowledge_tool = RetrieveKnowledgeTool()

# ================= 4. Agent 定义 =================

log_collector = Agent(
    role="高级日志采集与预处理专家",
    goal="读取日志文件，过滤噪音，提取关键安全事件，并统计攻击 IP。",
    backstory="""你是一名高效的数据工程师。
    你的任务不是逐行阅读所有日志，而是使用工具快速提取出最有价值的安全信息（如失败登录、非法用户、高频 IP）。
    你将输出一个包含统计数据和关键样本的精简报告。""",
    tools=[log_tool],
    llm=MODEL_NAME,
    allow_delegation=False,
    verbose=True
)

security_analyst = Agent(
    role="资深网络安全分析师",
    goal="基于预处理后的统计数据和样本日志，撰写深度安全分析报告。",
    backstory="""你拥有 10 年经验。
    你不需要重新数 IP 次数（工具已经统计好了），你需要做的是：
    1. 解读 Top IP 的攻击意图。
    2. 分析样本日志中的攻击手法。
    3. 结合知识库给出防御建议。
    4. 生成专业的《安全分析报告》。""",
    tools=[knowledge_tool],
    llm=MODEL_NAME,
    allow_delegation=False,
    verbose=True
)

# ================= 5. 任务定义 =================

task_collect = Task(
    description="""
    使用 read_log_file 工具处理路径为 {log_path} 的文件。
    输出要求：直接输出工具返回的精简报告（包含统计数据和样本）。
    """,
    expected_output="包含 IP 统计和日志样本的精简报告字符串",
    agent=log_collector
)

task_analyze = Task(
    description="""
    基于上一步提供的【精简报告】（包含 IP 统计和样本日志）进行分析：
    1. **威胁概览**：总结攻击规模和主要特征。
    2. **攻击源分析**：详细解读 Top 3 IP 的行为模式。
    3. **防御建议**：
       - 针对 Top IP 的具体 iptables 命令。
       - 长期加固建议（如 Fail2Ban 配置思路）。
    
    注意：不要尝试重新统计 IP，直接使用报告中提供的数据。
    """,
    expected_output="一份结构清晰、专业且基于真实数据的 Markdown 格式《安全分析报告》",
    agent=security_analyst,
    context=[task_collect]
)

# ================= 6. Crew 组建 =================

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
    
    print("🚀 启动多 Agent 协作安全分析系统 (智能过滤版)...")
    inputs = {"log_path": "data/auth.log"}
    
    # 确保 reports 目录存在
    os.makedirs("reports", exist_ok=True)
    
    # 生成带时间戳的文件名
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"reports/security_report_{timestamp}.txt"
    
    try:
        result = crew.kickoff(inputs=inputs)
        
        # 构造最终输出字符串
        final_output = "\n" + "="*60 + "\n"
        final_output += "           🛡️  多 Agent 协作分析报告  🛡️\n"
        final_output += "="*60 + "\n"
        final_output += str(result) + "\n"
        final_output += "="*60 + "\n"
        
        # 1. 打印到屏幕
        print(final_output)
        print("✅ 协作完成。")
        
        # 2. 自动保存到文件
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(final_output)
        
        print(f"💾 报告已自动保存至: {output_file}")
        
    except Exception as e:
        error_msg = f"\n❌ 执行错误：{e}"
        print(error_msg)
        # 即使报错也记录到日志
        with open("reports/error_log.txt", "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {error_msg}\n")
        import traceback
        traceback.print_exc()
