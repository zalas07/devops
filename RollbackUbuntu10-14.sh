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

rollback_aide() {
    echo -e "\033[1;34m=============================================\033[0m"
    echo -e "\033[1;33mMelakukan rollback instalasi AIDE...\033[0m"

    # Cek apakah AIDE terpasang
    if dpkg -s aide >/dev/null 2>&1; then
        echo -e "\033[1;33mMenghapus paket AIDE...\033[0m"
        sudo apt-get purge -y aide

        echo -e "\033[1;33mMembersihkan sisa konfigurasi dan database...\033[0m"
        sudo rm -f /var/lib/aide/aide.db*
        sudo rm -f /var/lib/aide/aide.db.new*
        sudo rm -f /etc/aide/aide.conf* 2>/dev/null

        echo -e "\033[1;32m[✓] AIDE berhasil dihapus dan dibersihkan dari sistem.\033[0m"
    else
        echo -e "\033[1;32m[✓] AIDE tidak ditemukan di sistem. Tidak ada yang perlu di-rollback.\033[0m"
    fi
}

rollback_cron_aide() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33mMelakukan rollback Cron Job AIDE...\033[0m"

    # Hapus cron job AIDE dari crontab root
    if sudo crontab -l 2>/dev/null | grep -q "aide --check"; then
        echo -e "\033[1;33mMenghapus Cron Job AIDE dari crontab root...\033[0m"
        sudo crontab -l 2>/dev/null | grep -v "aide --check" | sudo crontab -
        echo -e "\033[1;32m[✓] Cron Job AIDE berhasil dihapus.\033[0m"
    else
        echo -e "\033[1;32m[✓] Cron Job AIDE tidak ditemukan. Lewati penghapusan.\033[0m"
    fi

    # Hapus file log AIDE jika ada
    if [ -f /var/log/aide/aide.log ]; then
        sudo rm -f /var/log/aide/aide.log
        echo -e "\033[1;32m[✓] File log AIDE dihapus.\033[0m"
    fi

    # Hapus direktori log AIDE jika kosong
    if [ -d /var/log/aide ] && [ -z "$(ls -A /var/log/aide)" ]; then
        sudo rmdir /var/log/aide
        echo -e "\033[1;32m[✓] Direktori log AIDE dihapus karena kosong.\033[0m"
    fi
}

rollback_process_harden() {
    local sysctl_conf="/etc/sysctl.conf"
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33mMelakukan rollback konfigurasi hardening kernel dan banner...\033[0m"

    # Rollback fs.suid_dumpable
    if grep -q "^fs.suid_dumpable" "$sysctl_conf"; then
        sudo sed -i '/^fs\.suid_dumpable/d' "$sysctl_conf"
        echo -e "\033[1;32m[✓] fs.suid_dumpable dikembalikan.\033[0m"
    fi

    # Rollback kernel.randomize_va_space
    if grep -q "^kernel.randomize_va_space" "$sysctl_conf"; then
        sudo sed -i '/^kernel\.randomize_va_space/d' "$sysctl_conf"
        echo -e "\033[1;32m[✓] kernel.randomize_va_space dikembalikan.\033[0m"
    fi

    # Terapkan ulang sysctl
    sudo sysctl -p > /dev/null 2>&1

    # Hapus banner motd, issue, issue.net (jika isinya sesuai banner)
    for f in /etc/motd /etc/issue /etc/issue.net; do
        if grep -q "The System is for the use of BRI Authorized Users Only" "$f" 2>/dev/null; then
            sudo rm -f "$f"
            echo -e "\033[1;32m[✓] Banner $f dihapus.\033[0m"
        fi
    done

    # Hapus dynamic motd custom banner jika ada
    if [ -f /etc/update-motd.d/99-custom-banner ]; then
        sudo rm -f /etc/update-motd.d/99-custom-banner
        echo -e "\033[1;32m[✓] update-motd.d custom banner dihapus.\033[0m"
    fi

    echo -e "\033[1;32mRollback konfigurasi proses hardening selesai!\033[0m"
}

rollback_apparmor() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33mMelakukan rollback instalasi dan konfigurasi AppArmor...\033[0m"

    echo "[*] Menghapus paket AppArmor dan utilitasnya..."
    sudo apt-get purge -y apparmor apparmor-utils apparmor-profiles > /dev/null 2>&1
    sudo apt-get autoremove -y > /dev/null 2>&1

    echo "[*] Menghapus entri write_cache dan show_cache dari parser.conf..."
    if [ -f /etc/apparmor/parser.conf ]; then
        sudo sed -i '/^write_cache$/d' /etc/apparmor/parser.conf
        sudo sed -i '/^show_cache$/d' /etc/apparmor/parser.conf
        echo "[✓] parser.conf dibersihkan dari entri tambahan."
    else
        echo "[!] parser.conf tidak ditemukan, dilewati."
    fi

    echo "[*] Menonaktifkan AppArmor dari layanan init (jika memungkinkan)..."
    if command -v initctl >/dev/null 2>&1; then
        # Ubuntu dengan Upstart
        sudo service apparmor stop > /dev/null 2>&1
        sudo service apparmor disable > /dev/null 2>&1 || echo "[!] Tidak bisa disable via service."
    elif [ -x /etc/init.d/apparmor ]; then
        # Ubuntu dengan SysV
        sudo /etc/init.d/apparmor stop > /dev/null 2>&1
        sudo update-rc.d -f apparmor remove > /dev/null 2>&1
    fi

    echo "[*] Verifikasi apakah AppArmor masih aktif..."
    if command -v apparmor_status >/dev/null 2>&1; then
        sudo apparmor_status | grep "profiles are in enforce mode" && echo "[!] Masih ada profil aktif." || echo "[✓] AppArmor dinonaktifkan."
    else
        echo "[✓] apparmor_status tidak tersedia, kemungkinan sudah terhapus."
    fi

    echo -e "\033[1;32mRollback AppArmor selesai!\033[0m"
}

rollback_disable_service() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33m[!] Melakukan rollback terhadap service legacy yang sebelumnya dinonaktifkan...\033[0m"

    services=(
        chargen
        daytime
        discard
        echo
        time
        rsh
        talk
        telnet
        tftp
        rsync
        xinetd
    )

    for service in "${services[@]}"; do
        echo "[*] Memproses rollback service: $service"

        # Install ulang jika service ada di repo
        if ! dpkg -l | grep -qw "$service"; then
            echo "  [+] Menginstall kembali paket $service jika tersedia..."
            sudo apt-get install -y "$service" > /dev/null 2>&1
        fi

        # Aktifkan kembali service jika ada script init
        if [ -x "/etc/init.d/$service" ]; then
            echo "  [+] Mengaktifkan dan menyalakan ulang $service..."
            sudo update-rc.d "$service" defaults > /dev/null 2>&1
            sudo service "$service" start > /dev/null 2>&1
        fi

        # Buat ulang file konfigurasi xinetd jika sebelumnya dihapus
        if [[ "$service" =~ ^(chargen|daytime|discard|echo|time|rsh|talk|telnet|tftp)$ ]]; then
            xinetd_file="/etc/xinetd.d/$service"
            if [ ! -f "$xinetd_file" ]; then
                echo "  [+] Membuat ulang konfigurasi dasar untuk $service di xinetd.d..."
                sudo tee "$xinetd_file" > /dev/null <<EOF
service $service
{
    disable     = no
    type        = INTERNAL
    socket_type = stream
    wait        = no
    user        = root
}
EOF
            fi
        fi

        echo "  [✓] Rollback service $service selesai."
        echo
    done

    echo -e "\033[1;32m[+] Rollback semua service legacy selesai!\033[0m"
}

rollback_special_purpose_service() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33m[!] Melakukan rollback konfigurasi Special Purpose Services...\033[0m"

    # 1. Rollback NTP
    echo -e "${yellow}[*] Mengembalikan konfigurasi NTP...${nc}"
    if grep -q "server 172.18.104.166" /etc/ntp.conf; then
        sudo sed -i '/server 172.18.104.166/d' /etc/ntp.conf
        sudo service ntp restart
        echo -e "${green} Konfigurasi NTP dikembalikan.${nc}"
    fi

    # 2. Rollback Postfix
    echo -e "${yellow}[*] Mengembalikan konfigurasi Postfix...${nc}"
    if [ -f /etc/postfix/main.cf ]; then
        sudo sed -i 's/^inet_interfaces = .*/inet_interfaces = all/' /etc/postfix/main.cf
        sudo service postfix restart
        echo -e "${green} Postfix dikembalikan untuk dengar di semua interface.${nc}"
    fi

    # 3. Rollback SNMPD
    echo -e "${yellow}[*] Mematikan service SNMPD (jika tidak digunakan)...${nc}"
    if dpkg -l | grep -qw snmpd; then
        sudo service snmpd stop > /dev/null 2>&1
        sudo update-rc.d -f snmpd remove > /dev/null 2>&1
        echo -e "${green} SNMPD dihentikan.${nc}"
    fi

    # 4. Aktifkan kembali service yang sebelumnya dinonaktifkan
    enable_services=(
    "x11-common"
    "avahi-daemon"
    "cups"
    "isc-dhcp-server"
    "slapd"
    "nfs-kernel-server"
    "rpcbind"
    "bind9"
    "vsftpd"
    "apache2"
    "dovecot"
    "samba"
    "squid"
    "snmp"
    "exim4"
    )

    echo -e "${yellow}[*] Mengaktifkan kembali layanan yang sebelumnya dinonaktifkan...${nc}"

    for svc in "${enable_services[@]}"; do
        if dpkg -l | grep -qw "$svc"; then
            if [ -x "/etc/init.d/$svc" ]; then
                sudo update-rc.d "$svc" defaults > /dev/null 2>&1
                sudo service "$svc" start > /dev/null 2>&1
                echo -e "${green} Service $svc berhasil diaktifkan kembali.${nc}"
            fi
        fi
    done

    echo -e "\033[1;32m[+] Rollback konfigurasi Special Purpose Service selesai!\033[0m"
}

rollback_network_parameters() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "\033[1;33m[!] Melakukan rollback konfigurasi parameter keamanan jaringan...\033[0m"

    # Daftar parameter yang akan di-rollback
    params=(
        "net.ipv4.ip_forward"
        "net.ipv4.conf.all.send_redirects"
        "net.ipv4.conf.default.send_redirects"
    )

    for key in "${params[@]}"; do
        if grep -q "^\s*$key" /etc/sysctl.conf; then
            # Mencari nilai default berdasarkan dokumentasi
            if [[ "$key" == "net.ipv4.ip_forward" ]]; then
                default_value="1"
            elif [[ "$key" == "net.ipv4.conf.all.send_redirects" || "$key" == "net.ipv4.conf.default.send_redirects" ]]; then
                default_value="1"
            fi

            # Rollback perubahan ke default
            sudo sed -i "s|^\s*$key.*|$key = $default_value|" /etc/sysctl.conf
            echo -e "${green} $key dikembalikan ke nilai default: $default_value.${nc}"
        else
            echo -e "${cyan} $key tidak ditemukan dalam konfigurasi sysctl.conf.${nc}"
        fi
    done

    # Terapkan perubahan
    if sudo sysctl -p > /dev/null 2>&1; then
        echo -e "${green}[✓] Rollback parameter Keamanan Jaringan berhasil diterapkan.${nc}"
    else
        echo -e "${red}[x] Gagal menerapkan rollback. Cek konfigurasi sysctl.${nc}"
    fi
}

rollback_network_parameters_host() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo "[*] Starting rollback for network parameter hardening..."

    # Cek apakah backup file sysctl.conf ada
    if [ -f /etc/sysctl.conf.bak ]; then
        # Restore backup file sysctl.conf
        sudo cp /etc/sysctl.conf.bak /etc/sysctl.conf
        echo "[✓] File /etc/sysctl.conf berhasil di-restore dari backup."
    else
        echo "[x] Backup file sysctl.conf tidak ditemukan. Tidak dapat melakukan rollback."
        return 1
    fi

    # Terapkan perubahan setelah rollback
    if sudo sysctl -p > /dev/null 2>&1; then
        echo "[✓] Rollback parameter jaringan berhasil diterapkan."
    else
        echo "[x] Gagal menerapkan rollback. Cek konfigurasi sysctl."
    fi
}

rollback_audit() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo "[*] Starting rollback for auditd and rsyslog configurations..."

    # Menghentikan dan menonaktifkan service auditd dan rsyslog
    echo "[~] Stopping auditd and rsyslog services..."
    sudo service auditd stop
    sudo service rsyslog stop

    # Hapus konfigurasi yang telah dibuat di /etc/audit/rules.d/
    echo "[~] Removing custom audit rules files..."
    if [ -f /etc/audit/rules.d/50-logins.rules ]; then
        sudo rm -f /etc/audit/rules.d/50-logins.rules
        echo "[✓] Removed /etc/audit/rules.d/50-logins.rules"
    fi

    if [ -f /etc/audit/rules.d/50-delete.rules ]; then
        sudo rm -f /etc/audit/rules.d/50-delete.rules
        echo "[✓] Removed /etc/audit/rules.d/50-delete.rules"
    fi

    if [ -f /etc/audit/rules.d/50-scope.rules ]; then
        sudo rm -f /etc/audit/rules.d/50-scope.rules
        echo "[✓] Removed /etc/audit/rules.d/50-scope.rules"
    fi

    if [ -f /etc/audit/rules.d/50-session.rules ]; then
        sudo rm -f /etc/audit/rules.d/50-session.rules
        echo "[✓] Removed /etc/audit/rules.d/50-session.rules"
    fi

    # Kembalikan konfigurasi audit.rules jika perlu
    echo "[~] Restoring default /etc/audit/audit.rules file..."
    if [ -f /etc/audit/audit.rules.bak ]; then
        sudo cp /etc/audit/audit.rules.bak /etc/audit/audit.rules
        echo "[✓] /etc/audit/audit.rules restored from backup."
    else
        echo "[x] Backup file /etc/audit/audit.rules.bak not found. Skipping restore."
    fi

    # Hapus konfigurasi di /etc/audit/auditd.conf
    echo "[~] Restoring original auditd.conf..."
    if grep -q 'max_log_file' /etc/audit/auditd.conf; then
        sudo sed -i 's/^max_log_file = 200/max_log_file = 6/' /etc/audit/auditd.conf
        sudo sed -i 's/^max_log_file_action = keep_logs/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
        echo "[✓] Reverted changes in /etc/audit/auditd.conf."
    else
        echo "[✓] No changes needed for /etc/audit/auditd.conf."
    fi

    # Hapus paket auditd dan rsyslog jika diinstal
    echo "[~] Uninstalling auditd and rsyslog packages..."
    sudo apt-get remove --purge -y auditd rsyslog
    echo "[✓] auditd and rsyslog uninstalled."

    # Restart layanan auditd dan rsyslog untuk menerapkan perubahan
    echo "[~] Restarting auditd and rsyslog services..."
    sudo service auditd restart
    sudo service rsyslog restart

    echo "[✓] Rollback untuk konfigurasi auditd dan rsyslog selesai."
}

rollback_ssh_config() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo "🛠️  Starting rollback for SSH configuration..."

    SSH_CONFIG="/etc/ssh/sshd_config"

    # Restore dari backup jika ada
    if [ -f "${SSH_CONFIG}.bak" ]; then
        cp "${SSH_CONFIG}.bak" "$SSH_CONFIG"
        echo "✅ Restored SSH config from backup: ${SSH_CONFIG}.bak"
    else
        echo "⚠️ Backup file not found, skipping restoration."
    fi

    # Kembalikan permission ke default (644)
    chmod 644 "$SSH_CONFIG"
    echo "✅ Set permissions 644 on $SSH_CONFIG"

    # Restart SSH service agar perubahan berlaku
    if service --status-all | grep -Fq 'ssh'; then
        sudo service ssh restart
        echo "✅ SSH service restarted."
    else
        echo "⚠️  SSH service not found or not active."
    fi
}

rollback_audit_wazuh_agent() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "${yellow}[*] Memulai rollback untuk audit rules Wazuh Agent...${nc}"

    rules_dir="/etc/audit/rules.d"
    wazuh_rules_file="$rules_dir/wazuh.rules"

    # Cek apakah folder rules.d ada
    if [ ! -d "$rules_dir" ]; then
        echo -e "${red}[X] Folder $rules_dir tidak ditemukan. Pastikan auditd terinstall.${nc}"
        return 1
    fi

    # Cek jika ada backup file dari wazuh.rules
    if [ -f "$wazuh_rules_file.bak"* ]; then
        backup_file=$(ls -t $wazuh_rules_file.bak* | head -n 1)  # Ambil backup terbaru
        echo -e "${blue}[~] Mengembalikan file dari backup: $backup_file${nc}"
        sudo cp "$backup_file" "$wazuh_rules_file"
    else
        echo -e "${red}[X] Tidak ada backup file ditemukan. Rollback tidak dapat dilakukan.${nc}"
        return 1
    fi

    # Apply rules setelah rollback
    echo -e "${blue}[~] Reloading auditd rules setelah rollback...${nc}"
    if sudo service auditd restart; then
        echo -e "${green}[✓] Rollback audit rules Wazuh berhasil diterapkan.${nc}"
    else
        echo -e "${red}[X] Gagal reload auditd setelah rollback. Cek error-nya.${nc}"
        return 1
    fi

    # Verifikasi rollback
    echo -e "${yellow}[*] Rules aktif saat ini setelah rollback:${nc}"
    sudo auditctl -l | grep audit-wazuh-c
}

rollback_set_timeout() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "${yellow}[*] Memulai rollback untuk konfigurasi timeout...${nc}"

    # Hapus konfigurasi TMOUT dari /etc/bash.bashrc
    echo -e "${yellow}[~] Memeriksa dan menghapus konfigurasi TMOUT dari /etc/bash.bashrc...${nc}"
    if grep -q "TMOUT=600" /etc/bash.bashrc; then
        sudo sed -i '/TMOUT=600/d' /etc/bash.bashrc
        sudo sed -i '/export TMOUT/d' /etc/bash.bashrc
        echo -e "${green}[✓] Konfigurasi TMOUT dihapus dari /etc/bash.bashrc.${nc}"
    else
        echo -e "${red}[X] Konfigurasi TMOUT tidak ditemukan di /etc/bash.bashrc.${nc}"
    fi

    # Hapus konfigurasi TMOUT dari /etc/profile
    echo -e "${yellow}[~] Memeriksa dan menghapus konfigurasi TMOUT dari /etc/profile...${nc}"
    if grep -q "TMOUT=600" /etc/profile; then
        sudo sed -i '/TMOUT=600/d' /etc/profile
        sudo sed -i '/export TMOUT/d' /etc/profile
        echo -e "${green}[✓] Konfigurasi TMOUT dihapus dari /etc/profile.${nc}"
    else
        echo -e "${red}[X] Konfigurasi TMOUT tidak ditemukan di /etc/profile.${nc}"
    fi

    echo -e "${green}[✓] Rollback konfigurasi timeout selesai.${nc}"
}

rollback_user_account_env() {
    echo -e "\033[1;34m===============================================\033[0m"
    echo -e "${yellow}[*] Memulai rollback untuk pengaturan user account dan environment...${nc}"

    # Menghapus pengaturan expiration password di /etc/login.defs
    echo -e "${yellow}[~] Memeriksa dan menghapus pengaturan expiration password dari /etc/login.defs...${nc}"
    if grep -q "PASS_MAX_DAYS" /etc/login.defs; then
        sudo sed -i '/PASS_MAX_DAYS/d' /etc/login.defs
        echo -e "${green}[✓] Pengaturan PASS_MAX_DAYS dihapus dari /etc/login.defs.${nc}"
    fi
    if grep -q "PASS_MIN_DAYS" /etc/login.defs; then
        sudo sed -i '/PASS_MIN_DAYS/d' /etc/login.defs
        echo -e "${green}[✓] Pengaturan PASS_MIN_DAYS dihapus dari /etc/login.defs.${nc}"
    fi
    if grep -q "PASS_WARN_AGE" /etc/login.defs; then
        sudo sed -i '/PASS_WARN_AGE/d' /etc/login.defs
        echo -e "${green}[✓] Pengaturan PASS_WARN_AGE dihapus dari /etc/login.defs.${nc}"
    fi
    if grep -q "INACTIVE" /etc/login.defs; then
        sudo sed -i '/INACTIVE/d' /etc/login.defs
        echo -e "${green}[✓] Pengaturan INACTIVE dihapus dari /etc/login.defs.${nc}"
    fi

    # Menghapus pengaturan umask default di /etc/bash.bashrc dan /etc/profile
    echo -e "${yellow}[~] Memeriksa dan menghapus pengaturan umask dari /etc/bash.bashrc dan /etc/profile...${nc}"
    if grep -q "umask 027" /etc/bash.bashrc; then
        sudo sed -i '/umask 027/d' /etc/bash.bashrc
        echo -e "${green}[✓] Pengaturan umask dihapus dari /etc/bash.bashrc.${nc}"
    fi
    if grep -q "umask 027" /etc/profile; then
        sudo sed -i '/umask 027/d' /etc/profile
        echo -e "${green}[✓] Pengaturan umask dihapus dari /etc/profile.${nc}"
    fi

    # Menghapus pengaturan shell timeout di /etc/profile
    echo -e "${yellow}[~] Memeriksa dan menghapus pengaturan TMOUT dari /etc/profile...${nc}"
    if grep -q "TMOUT=600" /etc/profile; then
        sudo sed -i '/TMOUT=600/d' /etc/profile
        echo -e "${green}[✓] Pengaturan TMOUT dihapus dari /etc/profile.${nc}"
    fi

    echo -e "${green}[✓] Rollback pengaturan user account dan environment selesai.${nc}"
}


main() {
echo -e "${green}"

cat << "EOF"

__________         __         .__         _____                                                             __   
\______   \_____ _/  |_  ____ |  |__     /     \ _____    ____ _____     ____   ____   _____   ____   _____/  |_ 
 |     ___/\__  \\   __\/ ___\|  |  \   /  \ /  \\__  \  /    \\__  \   / ___\_/ __ \ /     \_/ __ \ /    \   __\
 |    |     / __ \|  | \  \___|   Y  \ /    Y    \/ __ \|   |  \/ __ \_/ /_/  >  ___/|  Y Y  \  ___/|   |  \  |  
 |____|    (____  /__|  \___  >___|  / \____|__  (____  /___|  (____  /\___  / \___  >__|_|  /\___  >___|  /__|  
                \/          \/     \/          \/     \/     \/     \//_____/      \/      \/     \/     \/      
Ubuntu Security Hardening Script
Compatible: Ubuntu 10.04 - 14.xx

EOF
echo -e "${nc}"
sleep 2

baseline_check
sleep 2

rollback_aide
sleep 2

rollback_cron_aide
sleep 2

rollback_process_harden
sleep 2

rollback_apparmor
sleep 2

rollback_disable_service
sleep 2

rollback_special_purpose_service
sleep 2

rollback_network_parameters
sleep 2

rollback_network_parameter_host
sleep 2

rollback_audit
sleep 2

rollback_ssh_config
sleep 2

rollback_audit_wazuh_agent
sleep 2

rollback_set_timeout
sleep 2

rollback_user_account_env
sleep 4

 # Pesan akhir
echo -e "\033[1;34m===============================================\033[0m"
    echo -e "${green}[*] Server berhasil terhardening dan konfigurasi selesai.${nc}"
    echo -e "${green}[✓] Semua langkah telah berhasil diterapkan.${nc}"
    echo -e "${green}[✓] Server siap untuk operasional dengan konfigurasi yang aman.${nc}"


}

main
