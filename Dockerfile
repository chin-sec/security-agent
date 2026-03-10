# 1. 基础镜像
FROM python:3.10-slim

# 2. 设置工作目录
WORKDIR /app

# 3. 安装系统级依赖 (编译 C++ 扩展库必需)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# 4. 【关键步骤】复制依赖文件
# 这行指令把宿主机的 requirements.txt 复制到容器的 /app 目录
COPY requirements.txt .

# 5. 【关键步骤】安装 Python 依赖
# 利用 Docker 缓存机制：如果 requirements.txt 没变，这一步会使用缓存，加速构建
RUN pip install --no-cache-dir -r requirements.txt

# 6. 复制剩余的应用代码
# 这步在安装依赖之后，避免每次改代码都重新安装依赖
COPY . .

# 7. 创建数据目录
RUN mkdir -p /app/data /app/reports

# 8. 暴露端口
EXPOSE 8000

# 9. 设置环境变量
ENV LOG_BASE_DIR=/app/data
ENV CREWAI_TRACING_ENABLED=false
ENV CREWAI_TELEMETRY_DISABLED=true

# 10. 启动命令
CMD ["python", "api.py"]
