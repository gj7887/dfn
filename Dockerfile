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
    wget -O $APP_NAME 'https://github.com/apernet/hysteria/releases/download/app%2Fv2.7/hysteria-linux-amd64' && \
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
exec /app/hysteria server -c /app/config.yaml
EOF
RUN chmod +x /app/start.sh

EXPOSE $SERVER_PORT

CMD ["/app/start.sh"]
