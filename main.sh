#!/bin/bash

echo "========== 代理工具深度检测 =========="

KEYWORDS=("xray" "v2ray" "trojan" "naiveproxy" "hysteria" "sing-box" "ssserver" "shadowsocks" "clash")

SUSPICIOUS=0

echo ""
echo "🔍 1. 检测本地代理端口（核心特征）"
PORTS=("1080" "10808" "7890" "7891" "8388")

for p in "${PORTS[@]}"; do
    RESULT=$(ss -tulnp 2>/dev/null | grep ":$p ")
    if [ ! -z "$RESULT" ]; then
        echo "⚠️ 可疑端口: $p"
        echo "$RESULT"
        ((SUSPICIOUS++))
    fi
done

echo ""
echo "🔍 2. 检测异常长连接（核心）"
ss -antp | awk '
NR>1 {
    if ($1=="ESTAB") {
        split($4,a,":"); split($5,b,":");
        if (b[1] != "127.0.0.1" && b[1] != "::1") {
            print $0
        }
    }
}' | head -n 20

echo ""
echo "🔍 3. 检测高频外连IP（Top 10）"
ss -ant | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 10

echo ""
echo "🔍 4. 检测可疑进程（弱特征）"
ps aux | grep -E "$(IFS=\|; echo "${KEYWORDS[*]}")" | grep -v grep

echo ""
echo "🔍 5. 检测 systemd 服务"
systemctl list-units --type=service | grep -E "$(IFS=\|; echo "${KEYWORDS[*]}")"

echo ""
echo "🔍 6. 扫描配置文件特征（强特征）"

CONFIG_HITS=$(grep -R -E '"(vmess|vless|trojan|shadowsocks|inbounds|outbounds)"' /etc /root /home 2>/dev/null)

if [ ! -z "$CONFIG_HITS" ]; then
    echo "⚠️ 发现代理配置特征:"
    echo "$CONFIG_HITS" | head -n 20
    ((SUSPICIOUS++))
fi

echo ""
echo "🔍 7. 检测异常UDP流量（Hysteria/QUIC）"
ss -uapn | awk 'NR>1 {print}' | head -n 20

echo ""
echo "🔍 8. 检测可执行文件（防改名）"

find /usr/bin /usr/local/bin /opt /root -type f -executable 2>/dev/null | while read file; do
    strings "$file" 2>/dev/null | grep -E "v2ray|xray|trojan|shadowsocks" >/dev/null
    if [ $? -eq 0 ]; then
        echo "⚠️ 可疑二进制: $file"
        ((SUSPICIOUS++))
    fi
done

echo ""
echo "🔍 9. DNS异常检测（简单版）"
grep "nameserver" /etc/resolv.conf

echo ""
echo "========== 检测结果 =========="

if [ $SUSPICIOUS -eq 0 ]; then
    echo "✅ 未发现明显代理特征"
elif [ $SUSPICIOUS -lt 3 ]; then
    echo "⚠️ 存在轻微可疑迹象（建议人工复查）"
else
    echo "🚨 高度疑似存在代理/翻墙工具"
fi