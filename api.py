import os
import asyncio
import shutil
import uuid
import logging
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, PlainTextResponse

# 【修改点 1】删除了这行报错的代码：
# from uvicorn.logging import DefaultLoggingConfig

# 引入我们修改后的 crew 模块
from crew_agents_stream_mapreduce import create_crew, LOG_BASE_DIR

app = FastAPI(title="Security Log Agent API", version="1.0.0")

# 配置基础日志 (可选，让打印更清晰)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# 确保数据目录存在
os.makedirs(LOG_BASE_DIR, exist_ok=True)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "model": os.getenv("MODEL_NAME", "qwen-max")}

@app.post("/analyze")
async def analyze_log(
    file: Optional[UploadFile] = File(None),
    log_path: Optional[str] = Form(None),
    background_tasks: BackgroundTasks = None
):
    """
    分析日志文件。
    方式 1: 上传文件 (推荐) -> 文件保存到 /app/data，然后分析。
    方式 2: 指定路径 -> 直接分析容器内已存在的文件。
    """
    
    target_file_path = ""

    # 1. 处理文件上传
    if file:
        if not file.filename:
            raise HTTPException(status_code=400, detail="未提供文件名")
        
        # 生成唯一文件名防止冲突
        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        target_file_path = os.path.join(LOG_BASE_DIR, unique_filename)
        
        try:
            with open(target_file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            logging.info(f"✅ 文件已保存：{target_file_path}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"文件保存失败：{str(e)}")
    
    elif log_path:
        # 如果用户指定路径，检查是否存在
        test_path = os.path.join(LOG_BASE_DIR, log_path) if not os.path.isabs(log_path) else log_path
        if not os.path.exists(test_path):
            raise HTTPException(status_code=404, detail=f"文件未找到：{test_path}")
        target_file_path = test_path
    else:
        raise HTTPException(status_code=400, detail="必须上传文件或提供 log_path 参数")

    # 2. 异步执行 CrewAI (防止阻塞 API)
    # 注意：CrewAI 主要是 CPU 密集和 IO 等待，使用 to_thread 放入线程池
    try:
        result = await asyncio.to_thread(run_crew_analysis, target_file_path)
        return PlainTextResponse(content=result, media_type="text/markdown")
    except Exception as e:
        # 清理上传的文件 (如果是因为分析失败)
        if file and os.path.exists(target_file_path):
            os.remove(target_file_path)
        logging.error(f"分析过程出错：{str(e)}")
        raise HTTPException(status_code=500, detail=f"分析过程出错：{str(e)}")

def run_crew_analysis(file_path: str):
    """在线程中运行的阻塞函数"""
    try:
        logging.info(f"🚀 开始分析文件：{file_path}")
        crew = create_crew()
        result = crew.kickoff(inputs={"log_path": file_path})
        logging.info("✅ 分析完成")
        return str(result)
    except Exception as e:
        logging.error(f"CrewAI 执行失败：{str(e)}")
        raise e

if __name__ == "__main__":
    import uvicorn
    # 【修改点 2】简化启动命令，移除 log_config 参数，使用 uvicorn 默认配置
    # 这样兼容所有新版 uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
