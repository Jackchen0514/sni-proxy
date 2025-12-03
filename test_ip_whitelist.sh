#!/bin/bash

echo "=== SNI Proxy IP 白名单功能测试 ==="
echo ""

# 检查二进制文件
if [ ! -f "./target/release/sni-proxy" ]; then
    echo "错误: 找不到编译好的文件"
    exit 1
fi

echo "✓ 使用二进制: ./target/release/sni-proxy"
echo "✓ 编译时间: $(stat -c %y ./target/release/sni-proxy)"
echo ""

# 创建测试配置
cat > config-ip-test.json << 'EOFCONFIG'
{
  "listen_addr": "127.0.0.1:18443",
  "whitelist": [
    "www.example.com",
    "*.example.com"
  ],
  "ip_whitelist": [
    "127.0.0.1"
  ],
  "log": {
    "level": "info",
    "output": "stdout"
  }
}
EOFCONFIG

echo "✓ 创建测试配置: config-ip-test.json"
echo "  - 监听端口: 18443"
echo "  - IP 白名单: 仅 127.0.0.1"
echo ""

# 启动服务（后台）
echo "启动测试服务..."
./target/release/sni-proxy config-ip-test.json > /tmp/sni-proxy-test.log 2>&1 &
SERVER_PID=$!
sleep 2

# 检查服务是否启动
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "✗ 服务启动失败！"
    cat /tmp/sni-proxy-test.log
    exit 1
fi

echo "✓ 服务已启动 (PID: $SERVER_PID)"
echo ""

# 显示日志中的 IP 白名单加载信息
echo "=== 服务日志（IP 白名单相关） ==="
grep -E "(IP 白名单|IP.*127)" /tmp/sni-proxy-test.log | head -5
echo ""

# 测试从 127.0.0.1 连接（应该成功到达 SNI 检查）
echo "=== 测试 1: 从 127.0.0.1 连接 (应该通过 IP 检查) ==="
echo "尝试连接..."
timeout 2 openssl s_client -connect 127.0.0.1:18443 -servername www.example.com </dev/null > /tmp/test1.log 2>&1 || true
sleep 1

# 检查服务日志
if grep -q "127.0.0.1 通过白名单检查" /tmp/sni-proxy-test.log; then
    echo "✓ IP 白名单检查通过！"
elif grep -q "127.0.0.1 不在白名单中" /tmp/sni-proxy-test.log; then
    echo "✗ IP 白名单拒绝了 127.0.0.1（不应该发生）"
else
    echo "⚠ 没有看到 IP 检查日志（可能需要 debug 级别）"
fi

# 显示最近的服务日志
echo ""
echo "=== 最近的服务日志 ==="
tail -10 /tmp/sni-proxy-test.log
echo ""

# 停止服务
echo "停止测试服务..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "=== 测试完成 ==="
echo ""
echo "如果你的生产环境中 IP 白名单不生效，请检查："
echo "1. 使用的是否是最新编译的二进制文件"
echo "2. 是否有反向代理（nginx/haproxy）修改了客户端 IP"
echo "3. 配置文件是否正确加载（启动时查看日志）"
echo "4. 服务是否已重启"
