#!/bin/bash

# Проверка зависимостей
if ! command -v bc &> /dev/null || ! command -v curl &> /dev/null; then
    echo "Устанавливаем необходимые пакеты (curl, bc)..."
    sudo apt-get update && sudo apt-get install -y curl bc >/dev/null 2>&1
fi

# Базовый список (надежный)
BASIC_DOMAINS=(
    "www.microsoft.com" "www.apple.com" "www.cisco.com" "store.steampowered.com" 
    "steamcommunity.com" "www.adobe.com" "aws.amazon.com"
)

# Глубокий список (GeoDNS, CDN, тяжелый трафик)
DEEP_DOMAINS=(
    "www.microsoft.com" "update.microsoft.com" "www.apple.com" "swupdate.apple.com"
    "www.samsung.com" "www.cisco.com" "www.intel.com" "www.hp.com" "www.dell.com"
    "www.ibm.com" "aws.amazon.com" "gateway.icloud.com" "www.akamai.com"
    "www.fastly.com" "www.cloudflare.com" "store.steampowered.com" "steamcommunity.com"
    "www.epicgames.com" "www.ea.com" "www.ubisoft.com" "www.wikipedia.org"
    "www.yahoo.com" "www.bing.com" "www.mozilla.org" "www.adobe.com"
    "www.twitch.tv" "www.netflix.com" "www.spotify.com" "discord.com"
    "zoom.us" "github.com" "gitlab.com" "www.reddit.com" "www.pinterest.com"
    "vimeo.com" "soundcloud.com" "www.roblox.com" "www.nvidia.com" "www.amd.com"
    "www.playstation.com" "www.xbox.com" "www.oracle.com" "www.salesforce.com"
    "www.sap.com" "www.vmware.com" "www.autodesk.com" "www.canva.com" "slack.com"
)

scan_list() {
    local -n DOMAINS_REF=$1
    local MODE=$2
    local TEMP_FILE=$(mktemp)

    echo "📡 Начинаю сканирование (Доменов: ${#DOMAINS_REF[@]}). Пожалуйста, подождите..."
    
    for DOMAIN in "${DOMAINS_REF[@]}"; do
        # Пингуем домен через curl (TLS 1.3)
        TIME=$(curl -s -w "%{time_appconnect}\n" -o /dev/null "https://$DOMAIN" --tls-max 1.3 --tlsv1.3 --max-time 3)
        
        if [ -n "$TIME" ] && [ "$TIME" != "0.000000" ]; then
            MS=$(echo "$TIME * 1000" | bc | cut -d'.' -f1)
            echo "$MS $DOMAIN" >> "$TEMP_FILE"
        fi
    done

    echo ""
    echo "========================================="
    if [ "$MODE" == "basic" ]; then
        echo "Результаты базового сканирования:"
        echo "-----------------------------------------"
        sort -n "$TEMP_FILE" | while read -r ms domain; do
            printf "%-25s | %s мс\n" "$domain" "$ms"
        done
    else
        echo "🏆 ТОП-20 САМЫХ БЫСТРЫХ ДОМЕНОВ 🏆"
        echo "-----------------------------------------"
        printf "%-5s | %-25s | %s\n" "Место" "Домен" "Пинг (мс)"
        echo "-----------------------------------------"
        COUNT=1
        sort -n "$TEMP_FILE" | head -n 20 | while read -r ms domain; do
            printf "#%-4s | %-25s | %s мс\n" "$COUNT" "$domain" "$ms"
            ((COUNT++))
        done
    fi
    echo "========================================="
    rm -f "$TEMP_FILE"
}

# Меню скрипта
clear
echo "🛠 Утилита сканирования SNI для Xray Reality"
echo "-----------------------------------------"
echo "1) Быстрый тест (только проверенная база)"
echo "2) Глубокий поиск (ТОП-20 из расширенной базы тяжелых сайтов)"
echo "0) Выход"
echo "-----------------------------------------"
read -p "Выберите режим (0-2): " choice

case $choice in
    1)
        scan_list BASIC_DOMAINS "basic"
        ;;
    2)
        scan_list DEEP_DOMAINS "deep"
        ;;
    0)
        echo "Выход."
        exit 0
        ;;
    *)
        echo "Неверный выбор."
        exit 1
        ;;
esac