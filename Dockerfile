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
    wget -O $APP_NAME 'https://github.com/apernet/hysteria/releases/download/app%2Fv2.6.2/hysteria-linux-amd64' && \
    chmod +x $APP_NAME && \
    openssl ecparam -genkey -name prime256v1 -out cert.key && \
    openssl req -new -x509 -key cert.key -out cert.pem -days 3650 -subj "/CN=localhost" && \
    rm -rf /var/lib/apt/lists/*

COPY --chmod=755 start.sh ./start.sh

RUN echo "listen: :${SERVER_PORT}\n\nauth:\n  type: password\n  password: $PW\n\ntls:\n  cert: ./cert.pem\n  key: ./cert.key" > config.yaml

EXPOSE $SERVER_PORT

CMD ["/app/start.sh"]
