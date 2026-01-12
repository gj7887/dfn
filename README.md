# Hysteria 2 部署项目

基于 Docker 和 Shell 脚本的 Hysteria 2 代理服务部署工具。

## 项目说明

本项目提供两种部署方式:
- **Docker 方式**: 通过 Docker 容器快速部署 Hysteria 2 服务
- **Shell 脚本方式**: 直接在 Linux 系统上安装运行

## 部署方式一: Docker

### 前置要求
- 已安装 Docker
- 服务器已开放相应端口(默认 443)

### 快速启动

1. **构建镜像**
```bash
docker build -t hysteria2-server .
```

2. **运行容器**
```bash
docker run -d \
  --name hysteria2 \
  -p 443:443 \
  -e SERVER_PORT=443 \
  -e SERVER_IP=你的服务器IP \
  -e PW=你的密码 \
  hysteria2-server
```

### 环境变量说明

| 变量 | 默认值 | 说明 |
|------|--------|------|
| APP_NAME | hysteria | 应用程序名称 |
| SNI | www.bing.com | TLS SNI 域名 |
| SERVER_PORT | 443 | 服务监听端口 |
| SERVER_IP | 127.0.0.1 | 服务器 IP 地址 |
| PW | changeme | 连接密码(必须修改) |

### 自定义配置

如需自定义配置,修改 Dockerfile 中的 ENV 变量后重新构建镜像。

---

## 部署方式二: Shell 脚本

### 前置要求
- Linux 系统
- wget 工具
- Root 或 sudo 权限

### 安装步骤

1. **下载并执行安装脚本**
```bash
chmod +x install.sh
sudo ./install.sh
```

2. **设置环境变量**
```bash
export SERVER_PORT=443
export SERVER_IP=你的服务器IP
```

3. **运行安装**
```bash
sudo ./install.sh
```

4. **按提示输入密码**
- 可手动输入密码
- 或留空自动生成随机密码

### 连接信息

安装完成后,连接信息会保存在 `app/hy2.txt` 文件中:

```
hy2://你的密码@服务器IP:端口?sni=www.bing.com&insecure=1&alpn=h3#lunes_hy2
```

---

## GitHub Actions 自动构建

项目包含 GitHub Actions 工作流,当 `Dockerfile` 或工作流文件更新时自动构建并推送镜像到 GHCR。

### 配置步骤

1. 修改 `.github/workflows/build-docker-image.yml` 中的 `IMAGE_NAME`
2. 在仓库 Settings 中启用 GitHub Container Registry
3. 推送代码到 `main` 或 `master` 分支触发自动构建

---

## 客户端配置

将生成的连接地址导入支持 Hysteria 2 协议的客户端即可使用。

推荐的客户端:
- [Hysteria 2 官方客户端](https://github.com/apernet/hysteria)
- Sing-box
- Xray-core
- Clash Meta

---

## 注意事项

1. **安全警告**: 默认密码为 `changeme`,部署前务必修改
2. **防火墙**: 确保服务器防火墙已开放指定端口
3. **证书**: 默认使用自签名证书,生产环境建议使用真实证书
4. **SNI**: 可根据需要修改 SNI 域名伪装流量

---

## 故障排查

### 端口被占用
```bash
# 检查端口占用
netstat -tunlp | grep 443
# 或
lsof -i :443
```

### Docker 容器无法启动
```bash
# 查看容器日志
docker logs hysteria2

# 进入容器检查
docker exec -it hysteria2 /bin/bash
```

### Shell 安装失败
检查:
1. `SERVER_PORT` 和 `SERVER_IP` 环境变量是否已设置
2. 网络连接是否正常
3. 是否有足够的权限

---

## 许可证

本脚本仅供学习交流使用,请遵守当地法律法规。
