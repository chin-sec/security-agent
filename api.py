import os
import asyncio
import shutil
import uuid
import logging
import re
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from crew_agents_stream_mapreduce import create_crew, LOG_BASE_DIR

# 初始化应用
app = FastAPI(title="Security Log Agent API", version="2.0.0")

# 配置日志
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# --- 安全配置 ---
ALLOWED_EXTENSIONS = {"log", "txt"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB 限制

# 确保数据目录存在
os.makedirs(LOG_BASE_DIR, exist_ok=True)

# 挂载静态文件目录 (用于存放 index.html, css, js)
# 确保 static 目录存在，否则启动会报错
if not os.path.exists("static"):
    os.makedirs("static")
app.mount("/static", StaticFiles(directory="static"), name="static")

def validate_filename(filename: str) -> str:
    """安全校验文件名，防止路径遍历"""
    # 只保留文件名部分，去除任何路径信息
    safe_name = os.path.basename(filename)
    if not safe_name:
        raise HTTPException(status_code=400, detail="无效的文件名")
    
    # 检查扩展名
    ext = safe_name.rsplit('.', 1)[-1].lower() if '.' in safe_name else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"不支持的文件类型: .{ext}。仅允许 .log, .txt")
    
    return safe_name

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """返回美化后的首页"""
    index_path = os.path.join("static", "index.html")
    if not os.path.exists(index_path):
        # 如果静态文件丢失，返回一个简单的错误提示
        return HTMLResponse(content="<h1>Error: Frontend files missing.</h1>", status_code=500)
    return FileResponse(index_path)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "model": os.getenv("MODEL_NAME", "qwen-max")}

@app.post("/analyze")
async def analyze_log(
    file: Optional[UploadFile] = File(None),
    log_path: Optional[str] = Form(None),
    background_tasks: BackgroundTasks = None
):
    target_file_path = ""

    # 1. 处理文件上传 (安全加固版)
    if file:
        if not file.filename:
            raise HTTPException(status_code=400, detail="未提供文件名")
        
        # 安全校验文件名
        safe_filename = validate_filename(file.filename)
        
        # 生成唯一文件名，彻底防止覆盖和路径遍历
        unique_filename = f"{uuid.uuid4()}_{safe_filename}"
        target_file_path = os.path.join(LOG_BASE_DIR, unique_filename)
        
        # 检查文件大小 (通过读取流的前几个字节或直接检查 header，这里简单处理)
        # 注意：file.file 是流，需要在写入时控制，这里简化为直接写入，依赖 Nginx/网关限制更佳
        
        try:
            with open(target_file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # 二次确认文件已落入指定目录
            if not target_file_path.startswith(os.path.abspath(LOG_BASE_DIR)):
                os.remove(target_file_path)
                raise HTTPException(status_code=403, detail="非法的文件路径操作")

            logging.info(f"✅ 文件已安全保存：{target_file_path}")
        except Exception as e:
            if os.path.exists(target_file_path):
                os.remove(target_file_path)
            raise HTTPException(status_code=500, detail=f"文件保存失败：{str(e)}")
    
    elif log_path:
        # 2. 处理内部已有文件路径 (严格限制在 LOG_BASE_DIR 内)
        # 防止用户传入 ../../etc/passwd
        clean_path = os.path.basename(log_path) # 只取文件名
        test_path = os.path.join(LOG_BASE_DIR, clean_path)
        
        # 再次确认解析后的绝对路径是否在允许目录内
        if not os.path.abspath(test_path).startswith(os.path.abspath(LOG_BASE_DIR)):
            raise HTTPException(status_code=403, detail="禁止访问该路径")
            
        if not os.path.exists(test_path):
            raise HTTPException(status_code=404, detail=f"文件未找到：{clean_path}")
        
        # 检查扩展名
        ext = clean_path.rsplit('.', 1)[-1].lower() if '.' in clean_path else ''
        if ext not in ALLOWED_EXTENSIONS:
             raise HTTPException(status_code=400, detail=f"不支持分析该类型文件: .{ext}")
             
        target_file_path = test_path
    else:
        raise HTTPException(status_code=400, detail="必须上传文件或提供 log_path 参数")

    # 3. 异步执行 CrewAI
    try:
        # 在线程池中运行阻塞任务
        result = await asyncio.to_thread(run_crew_analysis, target_file_path)
        return PlainTextResponse(content=result, media_type="text/markdown")
    except Exception as e:
        # 失败清理 (可选策略：如果是上传的文件则删除，如果是已有文件则保留)
        if file and os.path.exists(target_file_path):
            os.remove(target_file_path)
        logging.error(f"分析过程出错：{str(e)}")
        raise HTTPException(status_code=500, detail=f"分析过程出错：{str(e)}")

def run_crew_analysis(file_path: str):
    """在线程中运行的阻塞函数"""
    try:
        logging.info(f"🚀 开始分析文件：{file_path}")
        # 建议：在 create_crew 内部也做一层文件读取的只读保护
        crew = create_crew()
        result = crew.kickoff(inputs={"log_path": file_path})
        logging.info("✅ 分析完成")
        return str(result)
    except Exception as e:
        logging.error(f"CrewAI 执行失败：{str(e)}")
        raise e

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
