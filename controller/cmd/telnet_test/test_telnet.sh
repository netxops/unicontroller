#!/bin/bash

# Telnet 测试脚本
# 使用系统的 telnet 命令测试连接

HOST="${1:-172.26.10.50}"
PORT="${2:-23}"

echo "=========================================="
echo "使用系统 telnet 命令测试连接"
echo "目标: $HOST:$PORT"
echo "=========================================="
echo ""

# 使用 telnet 命令连接
# 注意：系统 telnet 命令不支持直接传递用户名和密码
# 需要手动输入或使用 expect 脚本

if command -v telnet &> /dev/null; then
    echo "正在连接到 $HOST $PORT..."
    echo "提示: 如果需要登录，请在连接后手动输入用户名和密码"
    echo "按 Ctrl+] 然后输入 'quit' 退出"
    echo ""
    telnet "$HOST" "$PORT"
else
    echo "错误: 系统未安装 telnet 命令"
    echo "安装方法:"
    echo "  Ubuntu/Debian: sudo apt-get install telnet"
    echo "  CentOS/RHEL: sudo yum install telnet"
    exit 1
fi

