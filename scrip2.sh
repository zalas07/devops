#!/bin/bash

log() {

echo "[+] $1"

}

baseline_check() {
log "performing baseline configuration check..."

# 1. OS Check

log "Operating System Info:"
echo "Distributor : $(lsb_release -i | cut -f2)"
echo "Description : $(lsb_release -d | cut -f2)"
echo "Release     : $(lsb_release -r | cut -f2)"
echo "Codename    : $(lsb_release -c | cut -f2)"
echo ""

# 2. System File Type
log "File System (df -T):"
df -T | grep -v tmpfs
echo ""

# 3. Display all directory in /var:"
log "Directory listing under /var:"
ls -l /var | grep "^d"
echo ""

# 4. Home Directory Display
log "Directory Listing under /home:"
ls -l /home | grep "^d"
echo ""

}

main() {
echo ""

cat << "EOF"

__________         __         .__         _____                                                             __   
\______   \_____ _/  |_  ____ |  |__     /     \ _____    ____ _____     ____   ____   _____   ____   _____/  |_ 
 |     ___/\__  \\   __\/ ___\|  |  \   /  \ /  \\__  \  /    \\__  \   / ___\_/ __ \ /     \_/ __ \ /    \   __\
 |    |     / __ \|  | \  \___|   Y  \ /    Y    \/ __ \|   |  \/ __ \_/ /_/  >  ___/|  Y Y  \  ___/|   |  \  |  
 |____|    (____  /__|  \___  >___|  / \____|__  (____  /___|  (____  /\___  / \___  >__|_|  /\___  >___|  /__|  
                \/          \/     \/          \/     \/     \/     \//_____/      \/      \/     \/     \/      
Ubuntu Security Hardening Script
Compatible: Ubuntu 16.04 - 24.xx
EOF
echo ""

baseline_check

}
main
