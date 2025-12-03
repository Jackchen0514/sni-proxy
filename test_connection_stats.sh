#!/bin/bash

echo "=== 测试连接数统计功能 ==="
echo ""

# 启动服务（debug 日志级别）
echo "启动服务（使用 debug 日志级别）..."
./target/release/sni-proxy config-debug-ip.json > /tmp/sni-connections-test.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "✓ 服务已启动 (PID: $SERVER_PID)"
echo ""

# 模拟多个连接
echo "=== 模拟 5 个并发连接 ==="
for i in {1..5}; do
    echo "发送连接 #$i..."
    timeout 1 openssl s_client -connect 127.0.0.1:18443 -servername www.example.com </dev/null >/dev/null 2>&1 &
done

sleep 3

# 显示连接统计日志
echo ""
echo "=== 连接统计日志 ==="
grep "📊" /tmp/sni-connections-test.log | tail -15

echo ""
echo "=== IP 白名单检查日志 ==="
grep "✅ IP" /tmp/sni-connections-test.log | head -5

echo ""
echo "=== 总体统计 ==="
grep -E "(总连接数|活跃连接)" /tmp/sni-connections-test.log | tail -5

# 停止服务
echo ""
echo "停止服务..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "完整日志保存在: /tmp/sni-connections-test.log"
