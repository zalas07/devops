#!/bin/bash


green='\033[0;32m'
yellow='\033[1;33m'
red='\033[0;31m'
blue='\033[0;34m'
nc='\033[0m'

log() {

color=$1
message=$2
echo -e "${color}${message}${nc}"

}


baseline_check() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;31mPerforming baseline configuration check...\033[0m"
    sleep 1

    # 1. OS Check
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33mChecking Operating System System Info...\033[0m"

    echo "Operating System Info:"
    if command -v lsb_release >/dev/null 2>&1; then
        echo "Distributor : $(lsb_release -i | cut -f2)"
        echo "Description : $(lsb_release -d | cut -f2)"
        echo "Release     : $(lsb_release -r | cut -f2)"
        echo "Codename    : $(lsb_release -c | cut -f2)"
    else
        # Fallback jika lsb_release tidak ada
        echo "Distributor : $(cat /etc/issue | awk '{print $1}')"
        echo "Description : $(cat /etc/issue)"
        echo "Release     : $(uname -r)"
        echo "Codename    : $(cat /etc/lsb-release 2>/dev/null | grep CODENAME | cut -d= -f2)"
    fi
    echo ""
    sleep 2

    # 2. System File Type
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33mChecking System File Type...\033[0m"
    echo "File System (df -T):"
    if df -T >/dev/null 2>&1; then
        df -T | grep -v tmpfs
    else
        # Ubuntu versi sangat lama mungkin tidak punya df -T
        echo "Perintah 'df -T' tidak tersedia, gunakan 'df' biasa:"
        df | grep -v tmpfs
    fi
    echo ""
    sleep 2

    # 3. Display all directory in /var:
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33mDirectory listing under /var:\033[0m"
    ls -l /var | grep "^d"
    echo ""
    sleep 2

    # 4. Home Directory Display
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33mDirectory listing under /home:\033[0m"
    ls -l /home | grep "^d"
    echo ""
    sleep 2
}
