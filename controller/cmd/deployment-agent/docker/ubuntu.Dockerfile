# 使用多阶段构建
FROM golang:1.23 AS builder

# 设置环境变量
ENV GONOPROXY='github.com/netxops'
ENV GONOSUMDB='github.com/netxops'
ENV GOPRIVATE='github.com/netxops'
ENV GOPROXY='https://goproxy.cn,direct'

# 设置工作目录
WORKDIR /app

# 复制源代码
COPY .. .

# 设置 GitHub token
ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"


# 编译代码
RUN go build -o deployment-agent ./cmd/deployment-agent

# 使用 Ubuntu 作为最终镜像
FROM jrei/systemd-ubuntu:20.04

# 安装必要的依赖
RUN apt-get update && apt-get install -y systemd curl

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /app/deployment-agent /usr/local/bin/

# 复制测试脚本并添加执行权限
COPY cmd/deployment-agent/docker/test-script.sh /
RUN chmod +x /test-script.sh

# 确保脚本使用 LF 换行符
RUN sed -i 's/\r$//' /test-script.sh

# 显示脚本内容和权限
RUN cat /test-script.sh && ls -l /test-script.sh

COPY cmd/deployment-agent/start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]




