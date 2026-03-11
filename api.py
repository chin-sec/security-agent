import sys
import os
import uuid
import logging
import re
import time
import asyncio  # ✅ 已添加：修复 NameError
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor

# FastAPI & Pydantic
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# 导入分析模块
try:
    from tools.log_tools import read_log_file
    from simple_analyzer import analyze_log
except ImportError as e:
    logging.error(f"CRITICAL: Import error - {e}")
    read_log_file = None
    analyze_log = None

# ================= 配置区域 =================
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_BASE_DIR = os.getenv("LOG_DATA_DIR", os.path.join(PROJECT_ROOT, "data"))
UPLOAD_FOLDER = os.path.join(LOG_BASE_DIR, "uploads")
MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_MB", "5")) * 1024 * 1024
ALLOWED_EXTENSIONS = {"txt", "log", "csv", "json"}
ALLOWED_MIME_TYPES = {"text/plain", "text/csv", "application/json", "text/markdown", "application/octet-stream"}

# 初始化日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# 确保目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ================= FastAPI 应用 =================
app = FastAPI(
    title="Secure Log Analysis API",
    description="Production-ready API for AI-powered security log analysis.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= 数据模型 =================

class AnalysisRequest(BaseModel):
    file_path: str = Field(..., description="Relative path to the log file (e.g., uploads/file.log).")
    analysis_type: str = Field(default="security", description="Type of analysis.")
    custom_prompt: Optional[str] = Field(None, description="Optional custom prompt.")

    @field_validator('file_path')
    @classmethod
    def validate_file_path(cls, v):
        if not v:
            raise ValueError("File path cannot be empty")
        if v.startswith("/") or ".." in v:
            raise ValueError("Invalid file path: Absolute paths and traversal forbidden")
        if not re.match(r'^[a-zA-Z0-9_./\-]+$', v):
            raise ValueError("Invalid characters in file path")
        if not v.startswith("uploads/"):
            raise ValueError("File path must start with 'uploads/'")
        return v

class AnalysisResponse(BaseModel):
    status: str
    message: str
    result: Optional[str] = None
    file_used: Optional[str] = None
    processing_time_ms: Optional[float] = None

# ================= 辅助函数 =================

def secure_filename(filename: str) -> str:
    filename = filename.replace('/', '_').replace('\\', '_')
    while filename.startswith('.'):
        filename = filename[1:]
    filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    return filename if filename else "unnamed_file"

def validate_file_content(file: UploadFile) -> tuple[bool, str]:
    ext = file.filename.split('.')[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Extension '.{ext}' not allowed."
    if file.content_type and file.content_type not in ALLOWED_MIME_TYPES:
        if file.content_type != 'application/octet-stream':
             return False, f"MIME type '{file.content_type}' not allowed."
    return True, "OK"

# ================= API 路由 =================

@app.get("/")
async def root():
    return {"service": "Secure Log Analysis API", "version": "2.0.0", "status": "running"}

@app.post("/upload", response_model=AnalysisResponse)
async def upload_log_file(file: UploadFile = File(...)):
    logger.info(f"Upload started: {file.filename}")
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")

    is_valid, msg = validate_file_content(file)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    safe_name = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{safe_name}"
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    temp_path = file_path + ".tmp"

    try:
        total_size = 0
        with open(temp_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                if not chunk: break
                total_size += len(chunk)
                if total_size > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail=f"File too large (> {MAX_UPLOAD_SIZE//1024//1024}MB)")
                buffer.write(chunk)
        
        os.rename(temp_path, file_path)
        relative_path = os.path.join("uploads", unique_filename)
        
        logger.info(f"Upload success: {relative_path}")
        return AnalysisResponse(status="success", message="File uploaded.", file_used=relative_path)

    except HTTPException:
        if os.path.exists(temp_path): os.remove(temp_path)
        raise
    except Exception as e:
        logger.error(f"Upload error: {e}", exc_info=True)
        if os.path.exists(temp_path): os.remove(temp_path)
        if os.path.exists(file_path): os.remove(file_path)
        raise HTTPException(status_code=500, detail="Internal upload error")

@app.post("/analyze", response_model=AnalysisResponse)
async def run_analysis(request: AnalysisRequest):
    if not read_log_file or not analyze_log:
        raise HTTPException(status_code=503, detail="Analysis engine not initialized")

    start_time = time.time()
    logger.info(f"Analysis requested: {request.file_path}")

    # 路径安全检查
    target_path = os.path.join(LOG_BASE_DIR, request.file_path)
    abs_target = os.path.abspath(target_path)
    abs_root = os.path.abspath(LOG_BASE_DIR)
    
    if not (abs_target.startswith(abs_root + os.sep) or abs_target == abs_root):
        raise HTTPException(status_code=403, detail="Access denied: Path traversal detected")
    
    if not os.path.exists(abs_target):
        raise HTTPException(status_code=404, detail="File not found")

    try:
        # 1. 读取文件
        log_content = read_log_file.invoke({"file_path": request.file_path})
        
        if not log_content or log_content.startswith(("Error", "Warning")):
            if "too large" in str(log_content).lower():
                raise HTTPException(status_code=400, detail="Log file too large")
            return AnalysisResponse(status="failed", message="Read error", result=log_content, file_used=request.file_path)

        # 2. 异步执行分析 (线程池)
        # ✅ 这里现在可以正常工作了，因为顶部已经 import asyncio
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=4) as pool:
            analysis_result = await loop.run_in_executor(pool, analyze_log, log_content)
        
        if not analysis_result or analysis_result.startswith("LLM 调用失败"):
            logger.error(f"LLM Error: {analysis_result}")
            raise HTTPException(status_code=500, detail="AI analysis failed")

        return AnalysisResponse(
            status="success",
            message="Analysis completed.",
            result=analysis_result,
            file_used=request.file_path,
            processing_time_ms=(time.time() - start_time) * 1000
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis unexpected error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal analysis error")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global Exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
