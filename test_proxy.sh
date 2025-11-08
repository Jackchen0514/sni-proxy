#!/bin/bash

# SNI 代理测试脚本

PROXY_HOST="localhost"
PROXY_PORT="8443"

echo "🧪 SNI 代理测试脚本"
echo "===================="
echo ""

# 测试白名单域名
echo "✅ 测试白名单域名 (应该成功):"
echo "测试 www.example.com ..."
timeout 5 openssl s_client -connect ${PROXY_HOST}:${PROXY_PORT} -servername www.example.com < /dev/null 2>&1 | grep -i "connected" && echo "  ✓ 成功" || echo "  ✗ 失败"

echo ""
echo "测试 github.com ..."
timeout 5 openssl s_client -connect ${PROXY_HOST}:${PROXY_PORT} -servername github.com < /dev/null 2>&1 | grep -i "connected" && echo "  ✓ 成功" || echo "  ✗ 失败"

echo ""
echo "===================="
echo ""

# 测试非白名单域名
echo "❌ 测试非白名单域名 (应该被拒绝):"
echo "测试 www.blocked-domain.com ..."
timeout 5 openssl s_client -connect ${PROXY_HOST}:${PROXY_PORT} -servername www.blocked-domain.com < /dev/null 2>&1 | grep -i "connected" && echo "  ✗ 意外成功 (应该被拒绝)" || echo "  ✓ 正确拒绝"

echo ""
echo "===================="
echo "测试完成!"
