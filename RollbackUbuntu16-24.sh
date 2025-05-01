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
log "$blue" "==============================================="
log "$red" "performing baseline configuration check..."
sleep 1

# 1. OS Check
log "$blue" "==============================================="
log "$yellow" "Checking Operating System System Info..."

log "Operating System Info:"
echo "Distributor : $(lsb_release -i | cut -f2)"
echo "Description : $(lsb_release -d | cut -f2)"
echo "Release     : $(lsb_release -r | cut -f2)"
echo "Codename    : $(lsb_release -c | cut -f2)"
echo ""

sleep 2

# 2. System File Type
log "$blue" "==============================================="
log "$yellow" "Checking System File....."
log "File System (df -T):"
df -T | grep -v tmpfs
echo ""
sleep 2

# 3. Display all directory in /var:"
log "$blue" "==============================================="
log "$yellow" "Directory listing under /var:"
ls -l /var | grep "^d"
echo ""
sleep 2

# 4. Home Directory Display
log "$blue" "==============================================="
log "$yellow" "Directory Listing under /home:"
ls -l /home | grep "^d"
echo ""

}
sleep 2

rollback_aide() {
    log "$blue" "============================================="
    log "$yellow" "Melakukan rollback AIDE - Menghapus instalasi dan konfigurasi..."

    # Hapus paket AIDE jika terpasang
    if dpkg -s aide >/dev/null 2>&1; then
        sudo apt purge aide -y
        sudo apt autoremove -y
        log "$green" "Paket AIDE berhasil dihapus."
    else
        log "$green" "Paket AIDE tidak ditemukan, sudah terhapus sebelumnya."
    fi

    # Hapus file konfigurasi AIDE jika ada
    if [ -f /etc/aide/aide.conf ]; then
        sudo rm -f /etc/aide/aide.conf
        log "$green" "File konfigurasi /etc/aide/aide.conf dihapus."
    fi

    # Hapus database AIDE yang diinisialisasi
    if [ -f /var/lib/aide/aide.db ]; then
        sudo rm -f /var/lib/aide/aide.db
        log "$green" "Database AIDE di /var/lib/aide/aide.db dihapus."
    fi
    if [ -f /var/lib/aide/aide.db.new ]; then
        sudo rm -f /var/lib/aide/aide.db.new
        log "$green" "Database AIDE baru di /var/lib/aide/aide.db.new dihapus."
    fi

    # Hapus direktori log custom
    if [ -d /var/log/aide ]; then
        sudo rm -rf /var/log/aide
        log "$green" "Direktori log /var/log/aide dihapus."
    fi

    # Hapus cron job AIDE dari crontab root
    if sudo crontab -l | grep -q "aide --check"; then
        sudo crontab -l | grep -v "aide --check" | sudo crontab -
        log "$green" "Cron job AIDE dihapus dari crontab root."
    fi

    log "$blue" "Rollback AIDE selesai dilakukan."
}

rollback_cron_aide() {
    log "$yellow" "Rollback: Menghapus Cron Job AIDE dari sudo Crontab..."

    # Backup crontab dulu sebelum diubah
    sudo crontab -l > /tmp/current_crontab.bak 2>/dev/null

    # Hapus baris cron job aide jika ada
    sudo crontab -l 2>/dev/null | grep -v "aide --check" | sudo crontab -

    log "$green" "Cron Job AIDE berhasil dihapus dari crontab root."

    # Hapus file log dan direktori jika yakin tidak digunakan modul lain
    if [ -f /var/log/aide/aide.log ]; then
        sudo rm -f /var/log/aide/aide.log
        log "$blue" "File /var/log/aide/aide.log telah dihapus."
    fi

    if [ -d /var/log/aide ]; then
        sudo rmdir --ignore-fail-on-non-empty /var/log/aide 2>/dev/null
        log "$blue" "Direktori /var/log/aide dihapus (jika kosong)."
    fi
}

rollback_process_harden() {
    local sysctl_conf="/etc/sysctl.conf"
    log "$blue" "================================================="
    log "$yellow" "Rollback: Mengembalikan konfigurasi hardening process..."

    # Rollback parameter fs.suid_dumpable
    if grep -q "^fs.suid_dumpable" "$sysctl_conf"; then
        sudo sed -i '/^fs.suid_dumpable/d' "$sysctl_conf"
        log "$blue" "Parameter fs.suid_dumpable dihapus dari $sysctl_conf"
    fi

    # Rollback parameter kernel.randomize_va_space
    if grep -q "^kernel.randomize_va_space" "$sysctl_conf"; then
        sudo sed -i '/^kernel.randomize_va_space/d' "$sysctl_conf"
        log "$blue" "Parameter kernel.randomize_va_space dihapus dari $sysctl_conf"
    fi

    # Terapkan perubahan sysctl
    sudo sysctl -p > /dev/null 2>&1

    # Rollback banner MOTD, issue, issue.net
    log "$yellow" "Rollback: Menghapus banner login..."

    for file in /etc/motd /etc/issue /etc/issue.net; do
        if [ -f "$file" ]; then
            sudo truncate -s 0 "$file"
            log "$blue" "Isi $file dikosongkan."
        fi
    done

    # Hapus dynamic motd custom script
    if [ -f /etc/update-motd.d/99-custom-banner ]; then
        sudo rm -f /etc/update-motd.d/99-custom-banner
        log "$blue" "File /etc/update-motd.d/99-custom-banner dihapus."
    fi

    log "$green" "Rollback konfigurasi hardening process selesai."
}

rollback_apparmor() {
    echo "[*] Starting AppArmor rollback..."

    echo "[*] Disabling and stopping AppArmor service..."
    sudo systemctl disable apparmor > /dev/null 2>&1
    sudo systemctl stop apparmor > /dev/null 2>&1

    echo "[*] Removing AppArmor packages..."
    sudo apt purge -y apparmor apparmor-utils apparmor-profiles > /dev/null 2>&1
    sudo apt autoremove -y > /dev/null 2>&1

    echo "[*] Cleaning up parser.conf entries (write_cache, show_cache)..."
    if [ -f /etc/apparmor/parser.conf ]; then
        sudo sed -i '/^write_cache$/d' /etc/apparmor/parser.conf
        sudo sed -i '/^show_cache$/d' /etc/apparmor/parser.conf
        echo "[*] Cleaned parser.conf"
    fi

    echo "[+] AppArmor rollback completed!"
}

rollback_disable_service() {
    log "$blue" "================================================="
    log "$yellow" "[*] Mengaktifkan kembali service legacy (rollback)..."

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
        echo -e "[*] Memeriksa service: $service"

        # Cek apakah unit servicenya ada
        if systemctl list-unit-files | grep -qw "${service}.service"; then
            echo -e " [+] Mengaktifkan kembali dan memulai service: $service"
            sudo systemctl enable "$service" 2>/dev/null
            sudo systemctl start "$service" 2>/dev/null
        else
            echo -e " [-] Service $service tidak ditemukan di systemctl, mungkin belum pernah diinstal atau sudah dihapus."
        fi
        echo
    done

    echo -e "${green}[+] Selesai rollback semua service yang ditargetkan.${nc}"
    sleep 2
}

rollback_special_purpose_service(){
log "$blue" "===================================================="
log "$yellow" "[*] Melakukan Rollback Special Purpose Services...${nc}"

# 1. Rollback NTP
echo -e "${yellow}[*] Rollback konfigurasi NTP...${nc}"

if command -v timedatectl &> /dev/null; then
    echo -e "${blue}[i] Rollback systemd-timesyncd...${nc}"
    sudo sed -i '/^NTP=/d' /etc/systemd/timesyncd.conf
    sudo systemctl restart systemd-timesyncd.service
    sudo systemctl disable systemd-timesyncd.service
    sudo systemctl mask systemd-timesyncd.service
    echo -e "${green}[✓] systemd-timesyncd dikembalikan ke default.${nc}"
else
    echo -e "${blue}[i] Rollback NTP klasik...${nc}"
    sudo sed -i '/172\.18\.104\.166/d' /etc/ntp.conf
    sudo systemctl restart ntp
    echo -e "${green}[✓] ntp.conf dibersihkan dan service di-restart.${nc}"
fi

# 2. Rollback Postfix
echo -e "${yellow}[*] Rollback konfigurasi Postfix...${nc}"
if [ -f /etc/postfix/main.cf ]; then
    sudo sed -i 's/^inet_interface = loopback_only/#inet_interface = all/' /etc/postfix/main.cf
    sudo systemctl restart postfix > /dev/null 2>&1
    echo -e "${green}[✓] Postfix diatur ulang (komentar inet_interface).${nc}"
fi

# 3. Rollback SNMPD
echo -e "${yellow}[*] Rollback SNMPD...${nc}"
sudo systemctl disable snmpd > /dev/null 2>&1
sudo systemctl stop snmpd > /dev/null 2>&1
echo -e "${green}[✓] SNMPD dihentikan dan dinonaktifkan.${nc}"

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

echo -e "${yellow}[*] Mengaktifkan kembali service yang sebelumnya dimatikan...${nc}"

for svc in "${enable_services[@]}"; do
    if dpkg -l | grep -qw "$svc"; then
        sudo systemctl enable "$svc" > /dev/null 2>&1
        sudo systemctl start "$svc" > /dev/null 2>&1
        echo -e "${green} Service $svc diaktifkan kembali.${nc}"
    fi
done

echo -e "${green}[✓] Rollback Special Purpose Service selesai.${nc}"
}

rollback_network_parameters() {
    log "$blue" "=============================================="
    log "$yellow" "[*] Rollback parameter keamanan jaringan di /etc/sysctl.conf...${nc}"

    # Daftar parameter yang ingin dihapus/rollback
    params_to_remove=(
        "net.ipv4.ip_forward"
        "net.ipv4.conf.all.send_redirects"
        "net.ipv4.conf.default.send_redirects"
    )

    for param in "${params_to_remove[@]}"; do
        if grep -q "^$param" /etc/sysctl.conf; then
            sudo sed -i "/^$param/d" /etc/sysctl.conf
            echo -e "${green}[-] $param dihapus dari sysctl.conf.${nc}"
        else
            echo -e "${cyan}[i] $param tidak ditemukan di sysctl.conf, tidak perlu rollback.${nc}"
        fi
    done

    # Terapkan perubahan sysctl
    sudo sysctl -p > /dev/null
    echo -e "${green}[✓] Rollback parameter jaringan selesai dan diterapkan ulang.${nc}"
}

rollback_network_parameters_host() {
    echo "[*] Memulai rollback parameter jaringan host..."

    # Daftar parameter yang dihapus
    parameters_to_remove=(
        "net.ipv4.conf.all.accept_source_route"
        "net.ipv4.conf.default.accept_source_route"
        "net.ipv4.conf.all.accept_redirects"
        "net.ipv4.conf.default.accept_redirects"
        "net.ipv4.conf.all.secure_redirects"
        "net.ipv4.conf.default.secure_redirects"
        "net.ipv4.conf.all.log_martians"
        "net.ipv4.conf.default.log_martians"
        "net.ipv4.icmp_echo_ignore_broadcasts"
        "net.ipv4.icmp_ignore_bogus_error_responses"
        "net.ipv4.conf.all.rp_filter"
        "net.ipv4.conf.default.rp_filter"
        "net.ipv4.tcp_syncookies"
    )

    # Backup sebelum rollback (optional, bisa dihapus kalau tidak perlu)
    cp /etc/sysctl.conf /etc/sysctl.conf.bak-before-rollback-host

    for param in "${parameters_to_remove[@]}"; do
        if grep -q "^$param" /etc/sysctl.conf; then
            sudo sed -i "/^$param/d" /etc/sysctl.conf
            echo "[-] $param dihapus dari sysctl.conf"
        else
            echo "[i] $param tidak ditemukan, tidak perlu rollback."
        fi
    done

    # Terapkan ulang konfigurasi
    sudo sysctl -p > /dev/null

    echo "[✓] Rollback parameter jaringan host selesai."
}

rollback_audit() {
    echo -e "${yellow}[*] Memulai rollback auditd dan rsyslog...${nc}"

    # Hapus file rules audit
    echo -e "${yellow}[~] Menghapus file audit rules yang dibuat...${nc}"
    sudo rm -f /etc/audit/rules.d/50-logins.rules
    sudo rm -f /etc/audit/rules.d/50-delete.rules
    sudo rm -f /etc/audit/rules.d/50-scope.rules
    sudo rm -f /etc/audit/rules.d/50-session.rules
    echo -e "${green}[✓] Semua file rules.d yang terkait dihapus.${nc}"

    # Reset auditd.conf ke default nilai standar (hanya max_log_file dan max_log_file_action yang kita ubah)
    echo -e "${yellow}[~] Mengembalikan pengaturan auditd.conf ke default...${nc}"
    sudo sed -i 's/^max_log_file =.*/max_log_file = 8/' /etc/audit/auditd.conf
    sudo sed -i 's/^max_log_file_action =.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
    echo -e "${green}[✓] auditd.conf dikembalikan ke nilai default.${nc}"

    # Optional: Hapus file /etc/audit/audit.rules jika dibuat oleh script
    if grep -q "clock_time" /etc/audit/audit.rules; then
        echo -e "${yellow}[~] Menghapus file /etc/audit/audit.rules karena dibuat oleh script...${nc}"
        sudo rm -f /etc/audit/audit.rules
        echo -e "${green}[✓] /etc/audit/audit.rules dihapus.${nc}"
    fi

    # Matikan dan disable service jika diinginkan
    echo -e "${yellow}[~] Menonaktifkan service auditd dan rsyslog...${nc}"
    sudo systemctl stop auditd rsyslog
    sudo systemctl disable auditd rsyslog
    echo -e "${green}[✓] Service auditd dan rsyslog dinonaktifkan.${nc}"

    echo -e "${green}[✓] Rollback audit selesai.${nc}"
}

ssh_config_rollback() {
    echo "🔄 Rolling back SSH configuration..."

    SSH_CONFIG="/etc/ssh/sshd_config"
    SSH_BACKUP="${SSH_CONFIG}.bak"

    # Pastikan backup ada
    if [ -f "$SSH_BACKUP" ]; then
        sudo cp "$SSH_BACKUP" "$SSH_CONFIG"
        sudo chmod 644 "$SSH_CONFIG"
        echo "✅ Restored $SSH_CONFIG from backup."
    else
        echo "❌ Backup file $SSH_BACKUP not found. Rollback aborted."
        return 1
    fi

    # Restart SSH service agar rollback berlaku
    if systemctl is-active --quiet sshd; then
        sudo systemctl restart sshd
        echo "✅ SSH service restarted."
    elif systemctl is-active --quiet ssh; then
        sudo systemctl restart ssh
        echo "✅ SSH service restarted."
    else
        echo "⚠️  SSH service not found or not active."
    fi
}

rollback_wazuh_agent() {
    echo "🔄 Rolling back Wazuh Agent audit rules..."

    rules_dir="/etc/audit/rules.d"
    wazuh_rules_file="$rules_dir/wazuh.rules"

    # Cek kalau ada backup file terbaru
    latest_backup=$(ls -t "${wazuh_rules_file}".bak.* 2>/dev/null | head -n1)

    if [ -f "$latest_backup" ]; then
        sudo cp "$latest_backup" "$wazuh_rules_file"
        echo "✅ Restored $wazuh_rules_file from $latest_backup"
    else
        echo "⚠️  No backup found. Removing $wazuh_rules_file..."
        sudo rm -f "$wazuh_rules_file"
    fi

    # Reload auditd rules
    echo "🔄 Reloading auditd rules..."
    if sudo augenrules --load && sudo systemctl restart auditd; then
        echo "✅ Auditd rules reloaded successfully."
    else
        echo "❌ Failed to reload auditd rules."
        return 1
    fi

    # Verifikasi
    echo "📋 Active rules after rollback:"
    sudo auditctl -l | grep audit-wazuh-c || echo "✅ No Wazuh audit rule active."
}

rollback_timeout() {
    echo "🔄 Rolling back timeout configurations..."

    # Cek dan hapus konfigurasi timeout di /etc/bash.bashrc
    echo "🔍 Memeriksa dan menghapus konfigurasi timeout di /etc/bash.bashrc..."
    if grep -q "TMOUT=600" /etc/bash.bashrc; then
        sudo sed -i '/TMOUT=600/d' /etc/bash.bashrc
        sudo sed -i '/export TMOUT/d' /etc/bash.bashrc
        echo "✅ Konfigurasi TMOUT di /etc/bash.bashrc telah dihapus."
    else
        echo "⚠️  Konfigurasi TMOUT tidak ditemukan di /etc/bash.bashrc."
    fi

    # Cek dan hapus konfigurasi timeout di /etc/profile
    echo "🔍 Memeriksa dan menghapus konfigurasi timeout di /etc/profile..."
    if grep -q "TMOUT=600" /etc/profile; then
        sudo sed -i '/TMOUT=600/d' /etc/profile
        sudo sed -i '/export TMOUT/d' /etc/profile
        echo "✅ Konfigurasi TMOUT di /etc/profile telah dihapus."
    else
        echo "⚠️  Konfigurasi TMOUT tidak ditemukan di /etc/profile."
    fi

    echo "🔄 Konfigurasi timeout berhasil di-rollback."
}

rollback_user_account_env() {
    echo "🔄 Rolling back user account and environment configurations..."

    # Hapus pengaturan expiration password di /etc/login.defs
    echo "🔍 Memeriksa dan menghapus pengaturan expiration password di /etc/login.defs..."
    sed -i '/PASS_MAX_DAYS 90/d' /etc/login.defs
    sed -i '/PASS_MIN_DAYS 7/d' /etc/login.defs
    sed -i '/PASS_WARN_AGE 7/d' /etc/login.defs
    sed -i '/INACTIVE 30/d' /etc/login.defs
    echo "✅ Pengaturan expiration password telah dihapus dari /etc/login.defs."

    # Hapus pengaturan umask di /etc/bashrc dan /etc/profile
    echo "🔍 Memeriksa dan menghapus pengaturan umask di /etc/bashrc dan /etc/profile..."
    sed -i '/umask 027/d' /etc/bashrc
    sed -i '/umask 027/d' /etc/profile
    echo "✅ Pengaturan umask telah dihapus dari /etc/bashrc dan /etc/profile."

    # Hapus pengaturan TMOUT di /etc/profile
    echo "🔍 Memeriksa dan menghapus pengaturan TMOUT di /etc/profile..."
    sed -i '/TMOUT=600/d' /etc/profile
    echo "✅ Pengaturan TMOUT telah dihapus dari /etc/profile."

    echo "🔄 Konfigurasi user account dan environment berhasil di-rollback."
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
Compatible: Ubuntu 16.04 - 24.xx

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

rollback_audit
sleep 2

ssh_config_rollback
sleep 2

rollback_wazuh_agent
sleep 2
	
rollback_timeout
sleep 2

rollback_user_account_env
sleep 2

 # Pesan akhir
    echo -e "${green}[*] Server berhasil di rollback pada konfigurasi awal.${nc}"
    echo -e "${green}[✓] Semua langkah telah berhasil diterapkan.${nc}"


}

main
