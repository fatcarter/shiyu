# 拾语 (Shiyu) — 检索 Web UI 容器镜像
#
# 检索侧只用 Python 标准库, 所以镜像里没有任何第三方依赖; 数据(wecom.sqlite 与 media/)
# 通过卷挂载进来, 不打进镜像。容器里没有企业微信本体, 路径由下面的环境变量指定。
#
# 构建:  docker compose build        (或 docker build -t shiyu .)
# 运行:  docker compose up -d        → http://127.0.0.1:8765
# 命令行: docker compose run --rm --entrypoint python3 shiyu search/search.py "关键词"
#
# 注意 .dockerignore 已排除 data/ 与 keys/ —— 27GB 的媒体目录不进构建上下文,
# 密钥也绝不会被打进镜像。
FROM python:3.12-slim

WORKDIR /app

# wwconfig.py 在仓库根, search/ 是被 import 的包目录(webui 里 import search)
COPY wwconfig.py ./
COPY search/ ./search/

RUN useradd --create-home --uid 1000 wecom
USER wecom

# 容器内没有容器(企业微信数据目录)可发现, 这几项必须显式给; TZ 不设会按 UTC 显示时间
ENV WEWORK_DATA_ROOT=/data \
    WECOM_DB=/data/wecom.sqlite \
    WECOM_MEDIA_ROOT=/data/media \
    WECOM_WEBUI_HOST=0.0.0.0 \
    WECOM_WEBUI_PORT=8765 \
    TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

VOLUME ["/data"]
EXPOSE 8765

# 镜像里没有 curl, 用 python 自己探活
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ['WECOM_WEBUI_PORT']+'/').read()"

ENTRYPOINT ["python3", "search/webui.py"]
