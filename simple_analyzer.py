import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# 选择模型类型：可以从环境变量读取，也可以直接在这里修改
AI_MODEL = os.getenv("AI_MODEL", "qwen")  # 默认 qwen，可改为 deepseek

# 根据模型类型设置相应的 API 配置
if AI_MODEL == "deepseek":
    api_key = os.getenv("DEEPSEEK_API_KEY")
    base_url = "https://api.deepseek.com/v1"
    model_name = "deepseek-chat"
elif AI_MODEL == "qwen":
    api_key = os.getenv("QWEN_API_KEY")
    base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    model_name = "qwen-plus"  # 可换成 qwen-turbo 等
else:
    raise ValueError("不支持的 AI_MODEL，请设置为 'deepseek' 或 'qwen'")

if not api_key:
    raise ValueError(f"{AI_MODEL.upper()}_API_KEY 未设置，请检查 .env 文件")

client = OpenAI(api_key=api_key, base_url=base_url)

def read_log(filepath):
    with open(filepath, 'r') as f:
        return f.read()

def analyze_log(log_text):
    prompt = f"你是一个网络安全分析师。请分析以下日志，指出可疑行为和潜在攻击，并以Chinese给出建议：\n\n{log_text}"
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    log = read_log("data/auth.log")
    report = analyze_log(log)
    print("\n=== 分析报告 ===\n")
    print(report)
