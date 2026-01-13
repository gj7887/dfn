# syntax=docker/dockerfile:1
FROM debian:stable-slim

ENV APP_NAME=hysteria \
    SNI=www.bing.com \
    SERVER_PORT=443 \
    SERVER_IP=127.0.0.1 \
    PW=changeme

WORKDIR /app

RUN apt-get update && \
    apt-get install -y wget openssl ca-certificates && \
    wget -O $APP_NAME "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64" && \
    chmod +x $APP_NAME && \
    openssl ecparam -genkey -name prime256v1 -out cert.key && \
    openssl req -new -x509 -key cert.key -out cert.pem -days 3650 -subj "/CN=localhost" && \
    rm -rf /var/lib/apt/lists/*

RUN cat > config.yaml <<EOF
listen: :${SERVER_PORT}

auth:
  type: password
  password: $PW

tls:
  cert: ./cert.pem
  key: ./cert.key
EOF

RUN cat > start.sh <<'EOF'
#!/bin/bash
# 生成连接信息
conn="hy2://${PW}@${SERVER_IP}:${SERVER_PORT}?sni=${SNI}&insecure=1&alpn=h3#lunes_hy2"

# 输出原始连接信息
echo "========================================="
echo "Hysteria 2 Server Connection Info"
echo "========================================="
echo "Connection: $conn"
echo ""

# 生成 Base64 编码
b64=$(printf '%s' "$conn" | base64 -w0)
echo "Connection (Base64): $b64"
echo "========================================="

# 保存到文件
echo "$conn" > /app/hy2.txt
echo "$b64" > /app/hy2_base64.txt
echo "hy2_base64://$b64" > /app/hy2_base64_uri.txt
echo ""
echo "Connection files saved:"
echo "  - /app/hy2.txt"
echo "  - /app/hy2_base64.txt"
echo "  - /app/hy2_base64_uri.txt"
echo "========================================="

# 启动 Hysteria 2 服务
exec /app/hysteria server -c /app/config.yaml
EOF
RUN chmod +x /app/start.sh

EXPOSE $SERVER_PORT

CMD ["/app/start.sh"]
