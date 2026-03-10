# rag/build_vector_db.py
from sentence_transformers import SentenceTransformer
import chromadb
import os

# 1. 配置
# 中文知识库请使用 'BAAI/bge-small-zh-v1.5'，英文用 'BAAI/bge-small-en-v1.5'
MODEL_NAME = 'BAAI/bge-small-zh-v1.5' 
DB_PATH = './chroma_db'
COLLECTION_NAME = "security_knowledge"
DATA_FILE = 'data/security_knowledge.txt'

def build_database():
    # 检查数据文件
    if not os.path.exists(DATA_FILE):
        print(f"❌ 错误: 找不到数据文件 {DATA_FILE}")
        print("💡 请先创建该文件并填入安全知识内容。")
        return

    print(f"🚀 正在加载模型: {MODEL_NAME} ...")
    model = SentenceTransformer(MODEL_NAME)

    print(f"📖 正在读取知识库: {DATA_FILE} ...")
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        docs = [line.strip() for line in f if line.strip()]

    if not docs:
        print("❌ 错误: 数据文件为空。")
        return

    print(f"🔧 正在初始化 ChromaDB (持久化路径: {DB_PATH}) ...")
    # 新版 ChromaDB 初始化方式
    client = chromadb.PersistentClient(path=DB_PATH)
    
    # 获取或创建集合
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    # 避免重复添加 (简单策略：如果已有数据则清空重建，或者跳过)
    if collection.count() > 0:
        print(f"⚠️  检测到集合中已有 {collection.count()} 条数据，正在清空重建...")
        client.delete_collection(name=COLLECTION_NAME)
        collection = client.create_collection(name=COLLECTION_NAME)

    print(f"⚡ 正在生成嵌入并向量化 {len(docs)} 条记录 (这可能需要几分钟)...")
    # 批量处理以防内存溢出 (每批 100 条)
    batch_size = 100
    for i in range(0, len(docs), batch_size):
        batch_docs = docs[i:i+batch_size]
        batch_ids = [f"doc_{j}" for j in range(i, i+len(batch_docs))]
        embeddings = model.encode(batch_docs).tolist()
        
        collection.add(
            ids=batch_ids,
            embeddings=embeddings,
            documents=batch_docs
        )
        print(f"   - 已处理 {min(i+batch_size, len(docs))}/{len(docs)} 条")

    print(f"✅ 向量数据库构建完成！共存储 {collection.count()} 条安全知识。")
    print(f"📂 数据保存在: {os.path.abspath(DB_PATH)}")

if __name__ == "__main__":
    build_database()
