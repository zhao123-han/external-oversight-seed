# 跨平台外挂监管种子 . 企业级不可篡改部署
# 核心：只读 rootfs + 规则只读分发 + 非 root + 降权 + seccomp（见 docker-compose.yml）
FROM python:3.12-slim

# 不写字节码缓存，缩小可写面
ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 复制整个工具包（含 deploy/ 微服务与加固件）
COPY manifest.json kernel cli.py install.py adapters docs examples deploy /app/

# 规则在构建期即设为只读（运行时容器 --read-only + ro 卷再兜底 → 纵深防御）
RUN chmod 0444 /app/kernel/rules.json /app/kernel/.rules.sig \
 && useradd -m -u 10001 guard \
 && chown -R guard:guard /app

USER guard

# 容器以 --read-only 运行；入口为监管微服务（POST /evaluate）
EXPOSE 8080
ENTRYPOINT ["python", "/app/deploy/guard-service.py"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
