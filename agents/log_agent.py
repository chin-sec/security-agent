import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import create_react_agent, AgentExecutor
from langchain_core.tools import Tool
from langchain_core.prompts import PromptTemplate

# 导入你的工具函数
from tools.log_tools import read_log_file

load_dotenv()

# 配置 LLM
api_key = os.getenv("DASHSCOPE_API_KEY")
base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
model_name = os.getenv("QWEN_MODEL", "qwen-turbo")

if not api_key:
    raise ValueError("未找到 DASHSCOPE_API_KEY，请检查 .env 文件")

llm = ChatOpenAI(
    model=model_name,
    temperature=0,
    api_key=api_key,
    base_url=base_url
)

# 定义工具
tools = [
    Tool(
        name="ReadLog",
        func=read_log_file,
        description="输入日志文件的路径（例如 'data/auth.log'），用于读取该文件的完整内容。"
    )
]

# ReAct Prompt 模板
react_template = """Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Important: Stop generating immediately after the Final Answer. Do not add any extra text after the Final Answer.

Begin!

Question: {input}
Thought:{agent_scratchpad}"""

prompt = PromptTemplate.from_template(react_template)

# 创建 ReAct Agent
agent = create_react_agent(llm, tools, prompt)

# 创建执行器，开启容错处理
agent_executor = AgentExecutor(
    agent=agent, 
    tools=tools, 
    verbose=True,
    handle_parsing_errors=True
)

def run_agent(query):
    """
    运行 Agent 并返回结果
    """
    try:
        response = agent_executor.invoke({"input": query})
        return response.get("output", "Agent 未生成有效输出")
    except Exception as e:
        return f"Agent 执行出错: {str(e)}"
