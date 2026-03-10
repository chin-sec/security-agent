# tools/retrieval_tools.py
import os
import chromadb
from sentence_transformers import SentenceTransformer

# --- 全局单例配置 (避免每次调用都重载) ---
MODEL_NAME = 'BAAI/bge-small-zh-v1.5' # 必须与 build_vector_db.py 一致
DB_PATH = './chroma_db'
COLLECTION_NAME = "security_knowledge"

_model = None
_client = None
_collection = None

def get_retriever():
    """懒加载：只在第一次调用时初始化模型和数据库连接"""
    global _model, _client, _collection
    
    if _model is None:
        try:
            _model = SentenceTransformer(MODEL_NAME)
            _client = chromadb.PersistentClient(path=DB_PATH)
            
            # 尝试获取集合，如果不存在则返回 None
            try:
                _collection = _client.get_collection(name=COLLECTION_NAME)
            except Exception:
                _collection = None # 集合不存在
                
        except Exception as e:
            print(f"⚠️  初始化检索器失败: {e}")
            return None, None
            
    return _model, _collection

def retrieve_knowledge(query: str, top_k: int = 3) -> str:
    """
    检索安全知识库
    如果数据库未构建或查询失败，返回提示信息，不让 Agent 崩溃
    """
    model, collection = get_retriever()
    
    if collection is None:
        return "⚠️  安全知识库尚未构建或找不到。请先运行 'python rag/build_vector_db.py' 构建数据库。"
    
    try:
        query_emb = model.encode([query]).tolist()
        results = collection.query(query_embeddings=query_emb, n_results=top_k)
        
        if not results['documents'] or not results['documents'][0]:
            return "未找到相关的安全知识。"
            
        docs = results['documents'][0]
        # 格式化输出，让 Agent 更容易理解
        response = "📚 相关知识库检索结果:\n" + "\n".join([f"- {doc}" for doc in docs])
        return response
        
    except Exception as e:
        return f"❌ 检索过程中发生错误: {str(e)}"
