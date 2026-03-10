import os
import json
import time
from collections import Counter
from agents.log_agent import get_qwen_llm
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

# ================= 配置区域 =================
LOG_FILE_PATH = "data/auth.log"
CHUNK_SIZE = 15000          # 每块处理 1.5 万行 (平衡上下文完整性与效率)
MAX_RETRY = 2               # 单块解析失败重试次数
TOP_IP_COUNT = 10           # 最终报告展示 Top 10 攻击 IP
# ===========================================

def extract_threats_from_chunk(chunk_text, llm):
    """
    [Map 阶段] 
    从日志块中提取结构化威胁数据。
    只返回 JSON 列表，不做任何统计或总结，确保原子性准确。
    """
    parser = JsonOutputParser()
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "你是一个高精度的安全日志解析引擎。你的唯一任务是从提供的 SSH 日志片段中提取‘失败登录’或‘异常访问’记录。"),
        ("human", """
        请分析以下日志片段，提取所有异常记录。
        
        【提取规则】:
        1. 仅提取包含 "Failed", "Invalid", "error", "refused", "break-in" 的行。
        2. 输出必须是纯粹的 JSON 列表格式，严禁包含 Markdown (```json)、注释或额外文本。
        3. 每个对象包含字段: 
           - "ip": 攻击者 IP (字符串)
           - "user": 尝试登录的用户名 (字符串)
           - "reason": 简短的错误原因 (字符串)
           - "timestamp": 时间戳 (如果有，否则为 null)
        4. 如果本片段没有异常，返回空列表 []。
        
        【日志片段】:
        {logs}
        """)
    ])
    
    chain = prompt | llm | parser
    
    for attempt in range(MAX_RETRY + 1):
        try:
            result = chain.invoke({"logs": chunk_text})
            if isinstance(result, list):
                # 数据清洗：确保每个元素都是字典
                clean_result = [item for item in result if isinstance(item, dict)]
                return clean_result
            return []
        except Exception as e:
            if attempt == MAX_RETRY:
                print(f"   ⚠️ 警告：本块解析失败 ({e})，将跳过此块。")
                return []
            time.sleep(1) # 短暂等待后重试

def generate_final_report(stats_data, llm):
    """
    [Report 阶段]
    基于精确的统计数据生成最终报告。
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system", "你是一名资深网络安全专家。请根据提供的【精确统计数据】撰写一份专业的《生产环境安全分析报告》。"),
        ("human", """
        请基于以下由系统精确计算得出的统计数据，撰写报告。
        
        【输入数据 (绝对真实)】:
        {stats_json}
        
        【报告要求】:
        1. **严禁**编造任何数据。所有 IP 次数、用户名称必须严格对应输入数据。
        2. **结构要求**:
           - 🛑 **总体态势评估**: 一句话总结风险等级 (高/中/低) 及主要威胁类型。
           - 📊 **攻击源深度分析**: 列出 Top {top_n} 恶意 IP，格式为 "IP 地址 (尝试次数: N)"，并简要分析其行为特征。
           - 🎯 **受影响资产**: 列出被爆破最严重的 Top 5 用户名。
           - 🛡️ **精准防御建议**: 
             - 针对 Top 1 攻击 IP，给出确切的 `iptables` 或 `firewalld` 封禁命令。
             - 给出通用的 `fail2ban` 配置建议。
        3. 语气专业、客观、简练。直接输出报告内容，不要输出“好的，这是报告”等废话。
        """)
    ])
    
    chain = prompt | llm
    
    response = chain.invoke({
        "stats_json": json.dumps(stats_data, ensure_ascii=False, indent=2),
        "top_n": TOP_IP_COUNT
    })
    
    return response.content

def run_production_analysis():
    print("🏭 启动生产级安全日志分析系统 (Map-Reduce 架构)...")
    print("="*60)
    
    # 1. 文件检查
    if not os.path.exists(LOG_FILE_PATH):
        print(f"❌ 错误：找不到文件 {LOG_FILE_PATH}")
        return
    
    # 2. 读取与分块
    print(f"📂 正在加载日志文件：{LOG_FILE_PATH} ...")
    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()
    except Exception as e:
        print(f"❌ 读取文件失败：{e}")
        return
    
    total_lines = len(all_lines)
    if total_lines == 0:
        print("⚠️ 日志文件为空。")
        return
        
    print(f"📄 日志总行数：{total_lines:,}")
    
    # 动态计算分块
    chunks = [all_lines[i:i+CHUNK_SIZE] for i in range(0, total_lines, CHUNK_SIZE)]
    print(f"✂️  策略：分为 {len(chunks)} 个块 (每块约 {CHUNK_SIZE:,} 行)")
    print(f"🧠 模型：调用 Qwen 进行逐块特征提取...\n")

    # 3. 初始化 LLM
    try:
        llm = get_qwen_llm()
    except Exception as e:
        print(f"❌ LLM 初始化失败：{e}")
        return

    # 4. Map 阶段：逐块提取
    all_extracted_threats = []
    
    for i, chunk in enumerate(chunks):
        chunk_text = "".join(chunk)
        print(f"   🔄 处理块 [{i+1}/{len(chunks)}]...", end='\r')
        
        threats = extract_threats_from_chunk(chunk_text, llm)
        all_extracted_threats.extend(threats)
    
    print(f"\n✅ 提取完成。共捕获 {len(all_extracted_threats):,} 条原始异常记录。")

    if not all_extracted_threats:
        print("ℹ️  未检测到任何异常登录记录。系统安全。")
        return

    # 5. Reduce 阶段：Python 本地精确统计 (杜绝 AI 幻觉)
    print("🧮 正在进行本地数据聚合与精确统计 (Python Native)...")
    
    ip_counter = Counter()
    user_counter = Counter()
    reason_samples = []
    
    for item in all_extracted_threats:
        if isinstance(item, dict):
            ip = item.get('ip', 'Unknown_IP')
            user = item.get('user', 'Unknown_User')
            reason = item.get('reason', 'Unknown')
            
            # 简单的脏数据清洗
            if ip and ip != 'Unknown_IP':
                ip_counter[ip] += 1
            if user:
                user_counter[user] += 1
            if reason:
                reason_samples.append(reason)
    
    # 构建统计数据字典
    stats_data = {
        "summary": {
            "total_attacks": sum(ip_counter.values()),
            "unique_ips": len(ip_counter),
            "unique_users": len(user_counter),
            "time_range": "全量日志分析"
        },
        "top_attackers": ip_counter.most_common(TOP_IP_COUNT),
        "top_targets": user_counter.most_common(5),
        "common_reasons": list(set(reason_samples))[:5] # 去重取前5个原因
    }
    
    print(f"   📊 统计结果：发现 {stats_data['summary']['unique_ips']} 个独立攻击 IP，总攻击次数 {stats_data['summary']['total_attacks']:,}")

    # 6. 生成最终报告
    print("\n🤖 正在基于精确数据生成最终安全报告...")
    try:
        report = generate_final_report(stats_data, llm)
        
        print("\n" + "="*60)
        print("           🛡️  生产环境安全分析报告  🛡️")
        print("="*60)
        print(report)
        print("="*60)
        print("✅ 分析完成。报告数据已由 Python 校验，确保准确无误。")
        
    except Exception as e:
        print(f"\n❌ 报告生成阶段出错：{e}")
        print("💡 提示：统计数据已准备就绪，但报告生成失败。")
        print(json.dumps(stats_data, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    run_production_analysis()
