import os
from typing import Optional, Type
from langchain_core.tools import tool  # 【关键】必须从 langchain_core 导入
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings # 假设你用的是 HF Embeddings

# 配置嵌入模型 (请根据你实际使用的模型调整，这里假设是 text2vec)
# 如果你的 build_vector_db.py 用的是其他模型，请保持一致
EMBEDDING_MODEL_NAME = "shibing624/text2vec-base-chinese" 
VECTOR_DB_PATH = "chroma_db"

@tool
def retrieve_knowledge(query: str) -> str:
    """
    检索本地安全知识库，获取与查询内容相关的安全规则、防御建议或攻击特征。
    
    参数:
        query (str): 用户想要查询的安全主题，例如 'SSH 爆破防御', 'fail2ban 配置', 'SQL 注入特征'。
    
    返回:
        str: 检索到的相关知识片段，格式为纯文本。如果没有找到相关内容，返回提示信息。
    """
    try:
        if not os.path.exists(VECTOR_DB_PATH):
            return "Error: Vector database not found. Please run build_vector_db.py first."

        # 初始化 Embeddings
        # 注意：首次加载模型会下载文件，后续会从缓存读取
        embeddings = HuggingFaceEmbeddings(
            model_name=EMBEDDING_MODEL_NAME,
            model_kwargs={'device': 'cpu'}, # 如果有 GPU 可改为 'cuda'
            encode_kwargs={'normalize_embeddings': True}
        )

        # 加载向量数据库
        db = Chroma(
            persist_directory=VECTOR_DB_PATH,
            embedding_function=embeddings
        )

        # 执行检索 (取前 3 个最相关片段)
        docs = db.similarity_search(query, k=3)
        
        if not docs:
            return "No relevant knowledge found in the database."

        # 格式化输出
        results = []
        for i, doc in enumerate(docs):
            results.append(f"[Source {i+1}]: {doc.page_content}")
        
        return "\n\n".join(results)

    except Exception as e:
        return f"Error retrieving knowledge: {str(e)}"

__all__ = ["retrieve_knowledge"]
