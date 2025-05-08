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
install_aide() {
    echo -e "\033[1;34m=============================================\033[0m"
    echo -e "\033[1;33mMengecek apakah paket AIDE sudah terinstall atau belum......\033[0m"

    if ! dpkg -s aide >/dev/null 2>&1; then
        echo -e "\033[1;31mPaket AIDE belum terpasang\033[0m"
        echo -e "\033[1;33mMemulai instalasi....\033[0m"

        # Gunakan apt-get untuk Ubuntu lama
        sudo DEBIAN_FRONTEND=noninteractive apt-get update
        sudo DEBIAN_FRONTEND=noninteractive apt-get install aide -y

        if [ $? -eq 0 ]; then 
            echo -e "\033[1;32mAIDE berhasil diinstall!\033[0m"

           # echo -e "\033[1;33mMelakukan inisialisasi AIDE...\033[0m"
           # sudo aideinit

            # Salin hasil inisialisasi ke database default
           # if [ -f /var/lib/aide/aide.db.new ]; then
           #     sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
           # elif [ -f /var/lib/aide/aide.db.new.gz ]; then
            #    sudo cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            #fi

            #echo -e "\033[1;32mAIDE siap digunakan. Anda bisa mulai scan integritas dengan:\033[0m"
            #echo -e "\033[1;36msudo aide --check\033[0m"
        else
            echo -e "\033[1;31mAIDE gagal diinstall. Periksa koneksi internet atau repo!\033[0m"
            return 1
        fi
    else
        echo -e "\033[1;32mAIDE sudah terpasang\033[0m"
        echo -e "\033[1;34mVersi AIDE:\033[0m"
        aide --version | head -n 1
    fi
}


setup_cron_aide() {
echo -e "\033[1;34m===============================================\033[0m"
    log "$yellow" "Mengecek dan Menambahkan Cron Job AIDE..."

    # Buat direktori log AIDE jika belum ada
    if [ ! -d /var/log/aide ]; then
        sudo mkdir -p /var/log/aide
        sudo chown root:root /var/log/aide
        sudo chmod 750 /var/log/aide
        log "$green" "Direktori /var/log/aide dibuat."
    else
        log "$blue" "Direktori /var/log/aide sudah ada."
    fi

    # Buat file log jika belum ada
    if [ ! -f /var/log/aide/aide.log ]; then
        sudo touch /var/log/aide/aide.log
        sudo chown root:root /var/log/aide/aide.log
        sudo chmod 640 /var/log/aide/aide.log
        log "$green" "File /var/log/aide/aide.log dibuat."
    else
        log "$blue" "File /var/log/aide/aide.log sudah ada."
    fi

    sleep 1

    # Tambahkan cron job hanya jika belum ada
    cron_line="0 4 * * * /usr/bin/aide --check > /var/log/aide/aide.log 2>&1"
    if sudo crontab -l 2>/dev/null | grep -q "aide --check"; then
        log "$green" "Cron Job AIDE sudah terpasang."
    else
        log "$blue" "Menambahkan Cron Job AIDE ke crontab root..."
        (sudo crontab -l 2>/dev/null; echo "$cron_line") | sudo crontab -
        log "$green" "Cron Job AIDE berhasil ditambahkan!"
    fi

    sleep 1
}

apply_process_harden() {
    local sysctl_conf="/etc/sysctl.conf"

    echo -e "\033[1;34m===============================================\033[0m"
    log "$yellow" "Menambahkan parameter dumpable dan kernel randomize..."

    # Tambahkan atau update fs.suid_dumpable
    if grep -q "^fs.suid_dumpable" "$sysctl_conf"; then
        sudo sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/' "$sysctl_conf"
    else
        echo "fs.suid_dumpable = 0" | sudo tee -a "$sysctl_conf" > /dev/null
    fi
    sleep 1

    # Tambahkan atau update kernel.randomize_va_space
    if grep -q "^kernel.randomize_va_space" "$sysctl_conf"; then
        sudo sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' "$sysctl_conf"
    else
        echo "kernel.randomize_va_space = 2" | sudo tee -a "$sysctl_conf" > /dev/null
    fi
    sleep 1

    # Terapkan konfigurasi sysctl
    sudo sysctl -p > /dev/null 2>&1

    log "$green" "Parameter fs.suid_dumpable dan ASLR berhasil diterapkan"

    log "$blue" "================================================="
    log "$yellow" "Menambahkan banner message...."

    local banner="The System is for the use of BRI Authorized Users Only.
Individuals using this computer system without authority, or in excess of their authority,
are subject to having all of their activities on this system monitored and recorded by system personnel. in the course of monitoring Individuals improperly using this system or in the course of system maintenance, the activities of authorized users may also be monitored."


    # Pasang banner ke file yang umum digunakan
    echo "$banner" | sudo tee /etc/motd /etc/issue /etc/issue.net > /dev/null

    # Dynamic MOTD hanya jika direktori tersedia
    if [ -d /etc/update-motd.d ]; then
        echo "#!/bin/sh" | sudo tee /etc/update-motd.d/99-custom-banner > /dev/null
        echo "echo \"$banner\"" | sudo tee -a /etc/update-motd.d/99-custom-banner > /dev/null
        sudo chmod +x /etc/update-motd.d/99-custom-banner
        log "$green" "Dynamic MOTD (update-motd.d) berhasil dikonfigurasi."
    else
        log "$yellow" "[!] Direktori /etc/update-motd.d tidak ditemukan. Melewati konfigurasi dynamic motd."
    fi

    log "$green" "File motd, issue, dan issue.net berhasil diupdate."

    sleep 2
}

install_apparmor() {
echo -e "\033[1;34m===============================================\033[0m"
    echo "[*] Memperbarui repository..."
    sudo apt-get update -y > /dev/null 2>&1

    echo "[*] Menginstal AppArmor dan paket terkait..."
    sudo apt-get install -y apparmor apparmor-utils apparmor-profiles > /dev/null 2>&1

    echo "[*] Mengecek status AppArmor..."
    if ! sudo apparmor_status > /dev/null 2>&1; then
        echo "[!] AppArmor status check gagal. Periksa apakah modul kernel AppArmor aktif."
        exit 1
    fi

    echo "[*] Menambahkan write_cache dan show_cache ke parser.conf jika perlu..."
    if [ -f /etc/apparmor/parser.conf ]; then
        grep -qxF 'write_cache' /etc/apparmor/parser.conf || echo 'write_cache' | sudo tee -a /etc/apparmor/parser.conf > /dev/null
        grep -qxF 'show_cache' /etc/apparmor/parser.conf || echo 'show_cache' | sudo tee -a /etc/apparmor/parser.conf > /dev/null
    else
        echo "[!] File parser.conf tidak ditemukan. Lewati penambahan opsi."
    fi

    echo "[*] Reload semua profil AppArmor..."
    for profile in /etc/apparmor.d/*; do
        sudo apparmor_parser -r "$profile" > /dev/null 2>&1
    done

    echo "[*] Set semua profil ke enforce mode..."
    sudo aa-enforce /etc/apparmor.d/* > /dev/null 2>&1

    echo "[*] Memastikan AppArmor aktif saat booting..."
    # Untuk Ubuntu 10–14 biasanya menggunakan upstart atau sysvinit
    if command -v initctl >/dev/null 2>&1; then
        # Untuk Upstart
        sudo service apparmor restart > /dev/null 2>&1
    else
        # Untuk SysV
        sudo /etc/init.d/apparmor restart > /dev/null 2>&1
    fi

    echo "[*] Verifikasi status layanan AppArmor..."
    sudo apparmor_status | grep "profiles are in enforce mode" && echo "[+] AppArmor aktif dan enforce!" || echo "[!] AppArmor belum aktif sepenuhnya."

    echo "[+] Instalasi dan konfigurasi AppArmor selesai untuk Ubuntu legacy!"
}

disable_service() {
   echo -e "\033[1;34m===============================================\033[0m"
    log "$yellow" "[*] Menonaktifkan Service legacy yang tidak dibutuhkan..."

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
        echo -e "[*] Memeriksa Service: $service"

        # Cek apakah service sedang aktif via netstat
        port_open=$(sudo netstat -tulpn 2>/dev/null | grep -i "$service")

        # Cek status layanan via /etc/init.d
        if [ -x "/etc/init.d/$service" ]; then
            is_running=$(sudo service "$service" status 2>&1 | grep -E "start/running|is running|active")
        else
            is_running=""
        fi

        if [[ -n "$is_running" || -n "$port_open" ]]; then
            echo -e " Service $service AKTIF atau port terbuka, mencoba nonaktifkan..."

            # Stop dan disable jika ada init script-nya
            if [ -x "/etc/init.d/$service" ]; then
                sudo service "$service" stop 2>/dev/null
                sudo update-rc.d -f "$service" remove 2>/dev/null
            fi

            # Hapus konfigurasi xinetd jika ada
            sudo rm -f "/etc/xinetd.d/$service"

            echo -e " Service $service berhasil dinonaktifkan."
        else
            echo -e " Service $service tidak aktif dan port tidak terbuka."
        fi
        echo
    done

    echo -e "${green}[+] Selesai memproses semua service yang ditargetkan.${nc}"
    sleep 2
}

special_purpose_service() {
echo -e "\033[1;34m===============================================\033[0m"
log "$yellow" "[*] Menjalankan Special Purpose Services...${nc}"

# 1. Konfigurasi & Aktivasi NTP
echo -e "${yellow}[*] Mengecek dan mengonfigurasi NTP...${nc}"

if ! dpkg -l | grep -qw ntp; then
   sudo apt-get update
   sudo apt-get install ntp -y
fi

if grep -q "^server" /etc/ntp.conf; then
    sudo sed -i '/^server /d' /etc/ntp.conf
fi

echo "server 172.18.104.166" | sudo tee -a /etc/ntp.conf > /dev/null
sudo service ntp restart
sleep 2

echo -e "${yellow}[~] Mengecek koneksi ke NTP Server...${nc}"
if command -v ntpq &>/dev/null; then
    output=$(ntpq -p | grep "172.18.104.166")
    if [[ -n "$output" ]]; then
        echo -e "${green} NTP terkoneksi ke server 172.18.104.166:${nc}\n$output"
    else
        echo -e "${red} NTP tidak dapat terkoneksi ke server 172.18.104.166.${nc}"
    fi
else
    echo -e "${red} Perintah ntpq tidak tersedia.${nc}"
fi

# 2. Konfigurasi Postfix hanya untuk lokal
echo -e "${yellow}[*] Mengecek dan mengonfigurasi Postfix...${nc}"
if ! dpkg -l | grep -qw postfix; then
    echo -e "${yellow}[~] Menginstall Postfix, silahkan pilih 'Local Only' saat diminta.${nc}"
    sudo DEBIAN_PRIORITY=high apt-get install postfix -y
fi

if [ -f /etc/postfix/main.cf ]; then
   sudo sed -i 's/^inet_interfaces = .*/inet_interfaces = loopback-only/' /etc/postfix/main.cf
   sudo service postfix restart
   echo -e "${green} Postfix diatur hanya untuk localhost.${nc}"
fi

# 3. Konfigurasi SNMPD
echo -e "${yellow}[*] Mengecek dan Mengonfigurasi SNMPD...${nc}"
if ! dpkg -l | grep -qw snmpd; then
    sudo apt-get install snmpd -y > /dev/null 2>&1
fi
sudo service snmpd restart
sudo update-rc.d snmpd defaults
echo -e "${green} SNMPD diaktifkan.${nc}"

# 4. Daftar service yang perlu dinonaktifkan
disable_services=(
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

echo -e "${yellow}[*] Menonaktifkan service yang tidak diperlukan...${nc}"

for svc in "${disable_services[@]}"; do
    if dpkg -l | grep -qw "$svc"; then
        if [ -x "/etc/init.d/$svc" ]; then
            sudo service "$svc" stop > /dev/null 2>&1
            sudo update-rc.d -f "$svc" remove > /dev/null 2>&1
            echo -e "${green} Service $svc dinonaktifkan.${nc}"
        fi
    fi
done

echo -e "${green} Module Purpose Special service selesai.${nc}"
}

network_parameters() {
   echo -e "\033[1;34m===============================================\033[0m"
    log "$yellow" "[*] Menetapkan Parameter keamanan jaringan di /etc/sysctl.conf...${nc}"

    # Daftar parameter yang ingin di set
    params=(
        "net.ipv4.ip_forward=0"
        "net.ipv4.conf.all.send_redirects=0"
        "net.ipv4.conf.default.send_redirects=0"
    )

    for entry in "${params[@]}"; do
        key="${entry%%=*}"
        value="${entry##*=}"

        if grep -q "^\s*${key}" /etc/sysctl.conf; then
            current_value=$(grep "^\s*${key}" /etc/sysctl.conf | awk '{print $3}')
            if [[ "$current_value" == "$value" ]]; then
                echo -e "${green}[✓] $key sudah terset dengan nilai $value.${nc}"
            else
                sudo sed -i "s|^\s*${key}.*|$key = $value|" /etc/sysctl.conf
                echo -e "${yellow}[!] $key ditemukan, nilai diperbarui menjadi $value.${nc}"
            fi
        else
            echo "$key = $value" | sudo tee -a /etc/sysctl.conf > /dev/null
            echo -e "${cyan}[+] $key belum ada, ditambahkan dengan nilai $value.${nc}"
        fi
    done

    # Terapkan perubahan
    if sudo sysctl -p > /dev/null 2>&1; then
        echo -e "${green}[✓] Parameter Keamanan Jaringan berhasil diterapkan.${nc}"
    else
        echo -e "${red}[x] Gagal menerapkan parameter. Cek konfigurasi sysctl.${nc}"
    fi
}

network_parameters_host() {
echo -e "\033[1;34m===============================================\033[0m"
    echo "[*] Starting network parameter hardening..."

    # Backup dulu file sysctl.conf
    sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak

    # List parameter dan nilai yang ingin diset
    settings=(
        "net.ipv4.conf.all.accept_source_route=0"
        "net.ipv4.conf.default.accept_source_route=0"
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0"
        "net.ipv4.conf.default.secure_redirects=0"
        "net.ipv4.conf.all.log_martians=1"
        "net.ipv4.conf.default.log_martians=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1"
        "net.ipv4.icmp_ignore_bogus_error_responses=1"
        "net.ipv4.conf.all.rp_filter=1"
        "net.ipv4.conf.default.rp_filter=1"
        "net.ipv4.tcp_syncookies=1"
    )

    for entry in "${settings[@]}"; do
        key="${entry%%=*}"
        value="${entry##*=}"

        if grep -q "^\s*${key}" /etc/sysctl.conf; then
            sudo sed -i "s|^\s*${key}.*|$key = $value|" /etc/sysctl.conf
            echo "[+] Updated $key to $value"
        else
            echo "$key = $value" | sudo tee -a /etc/sysctl.conf > /dev/null
            echo "[+] Added $key = $value"
        fi
    done

    # Terapkan perubahan
    if sudo sysctl -p > /dev/null 2>&1; then
        echo "[✓] Network parameters hardening applied successfully."
    else
        echo "[x] Failed to apply sysctl settings. Please check manually."
    fi
}

audit() {
    echo "[*] Memulai konfigurasi auditd dan rsyslog..."

    # --- Install paket ---
    echo "[~] Memeriksa dan menginstal auditd & rsyslog..."
    sudo apt-get update -qq
    sudo apt-get install -y auditd rsyslog

    echo "[✓] Instalasi selesai."

    # --- Pastikan direktori rules.d ada ---
    sudo mkdir -p /etc/audit/rules.d

    # --- Fungsi bantu ---
    write_if_diff() {
        local filepath="$1"
        local content="$2"
        local tmpfile
        tmpfile=$(mktemp)
        echo "$content" > "$tmpfile"
        if [[ -f "$filepath" ]] && diff -q "$filepath" "$tmpfile" > /dev/null; then
            echo "[i] $filepath sudah sesuai, skip."
        else
            echo "[~] Menulis ulang $filepath..."
            echo "$content" | sudo tee "$filepath" > /dev/null
        fi
        rm -f "$tmpfile"
    }

    # === RULES ===
    write_if_diff "/etc/audit/rules.d/00-base.rules" "$(cat << 'EOF'
-D
-b 8192
-f 1
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
--backlog_wait_time 60000
EOF
)"

    write_if_diff "/etc/audit/rules.d/50-logins.rules" "$(cat << 'EOF'
-w /var/log/lastlog -p wa -k logins
EOF
)"

    write_if_diff "/etc/audit/rules.d/50-delete.rules" "$(cat << 'EOF'
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=500 -F auid!=4294967295 -k delete
EOF
)"

    write_if_diff "/etc/audit/rules.d/50-scope.rules" "$(cat << 'EOF'
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF
)"

    write_if_diff "/etc/audit/rules.d/50-session.rules" "$(cat << 'EOF'
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF
)"

    # === Konfigurasi auditd.conf ===
    echo "[~] Memeriksa /etc/audit/auditd.conf..."
    sudo sed -i 's/^max_log_file *=.*/max_log_file = 200/' /etc/audit/auditd.conf
    sudo sed -i 's/^max_log_file_action *=.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sudo sed -i 's/^space_left *=.*/space_left = 90/' /etc/audit/auditd.conf
    sudo sed -i 's/^space_left_action *=.*/space_left_action = ROTATE/' /etc/audit/auditd.conf
    sudo sed -i 's/^admin_space_left *=.*/admin_space_left = 80/' /etc/audit/auditd.conf
    sudo sed -i 's/^admin_space_left_action *=.*/admin_space_left_action = ROTATE/' /etc/audit/auditd.conf
    echo "[✓] auditd.conf dikonfigurasi."

    # === Reload Rules ===
    echo "[~] Memuat ulang aturan audit menggunakan auditctl..."
    sudo auditctl -R /etc/audit/rules.d/00-base.rules
    sudo auditctl -R /etc/audit/rules.d/50-logins.rules
    sudo auditctl -R /etc/audit/rules.d/50-delete.rules
    sudo auditctl -R /etc/audit/rules.d/50-scope.rules
    sudo auditctl -R /etc/audit/rules.d/50-session.rules

    # === Enable dan Restart Service ===
    echo "[~] Memulai ulang layanan auditd dan rsyslog..."
    sudo service auditd restart
    sudo service rsyslog restart

    echo "[✓] Konfigurasi auditd dan rsyslog selesai."
}




ssh_config() {
echo -e "\033[1;34m===============================================\033[0m"
    echo "🛠️  Starting SSH configuration hardening..."

    SSH_CONFIG="/etc/ssh/sshd_config"

    # Backup dulu sebelum ubah
    if [ ! -f "${SSH_CONFIG}.bak" ]; then
        cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"
        echo "✅ Backup created: ${SSH_CONFIG}.bak"
    fi

    # Pastikan permission 600
    chmod 600 "$SSH_CONFIG"
    echo "✅ Set permissions 600 on $SSH_CONFIG"

    # Update atau tambahkan konfigurasi
    update_or_append() {
        local key="$1"
        local value="$2"
        if grep -qE "^\s*${key}\s+" "$SSH_CONFIG"; then
            sed -i "s|^\s*${key}\s\+.*|${key} ${value}|g" "$SSH_CONFIG"
        else
            echo "${key} ${value}" >> "$SSH_CONFIG"
        fi
    }

    update_or_append "Protocol" "2"
    update_or_append "LogLevel" "INFO"
    update_or_append "X11Forwarding" "no"
    update_or_append "MaxAuthTries" "4"
    update_or_append "IgnoreRhosts" "yes"
    update_or_append "HostbasedAuthentication" "no"
    update_or_append "PermitRootLogin" "no"
    update_or_append "PermitEmptyPasswords" "no"
    update_or_append "PermitUserEnvironment" "no"
    update_or_append "MACs" "hmac-sha2-512,hmac-sha2-256"
    update_or_append "ClientAliveInterval" "300"
    update_or_append "ClientAliveCountMax" "0"
    update_or_append "LoginGraceTime" "60"

    echo "✅ SSH baseline configuration applied."

    # Restart SSH service agar perubahan berlaku
    if service --status-all | grep -Fq 'ssh'; then
        sudo service ssh restart
        echo "✅ SSH service restarted."
    else
        echo "⚠️  SSH service not found or not active."
    fi
}

audit_wazuh_agent() {
echo -e "\033[1;34m===============================================\033[0m"
    echo -e "${yellow}[*] Menambahkan audit rules untuk Wazuh Agent...${nc}"

    rules_dir="/etc/audit/rules.d"
    wazuh_rules_file="$rules_dir/wazuh.rules"

    # Cek apakah folder rules.d ada
    if [ ! -d "$rules_dir" ]; then
        echo -e "${red}[X] Folder $rules_dir tidak ditemukan. Pastikan auditd terinstall.${nc}"
        return 1
    fi

    # Kalau sudah ada file wazuh.rules, backup dulu
    if [ -f "$wazuh_rules_file" ]; then
        backup_file="${wazuh_rules_file}.bak.$(date +%s)"
        echo -e "${blue}[~] Membuat backup file: $backup_file${nc}"
        sudo cp "$wazuh_rules_file" "$backup_file"
    fi

    # Isi rules untuk Wazuh
    echo -e "${blue}[~] Menulis rules baru ke $wazuh_rules_file${nc}"
    sudo tee "$wazuh_rules_file" > /dev/null <<EOF
-a always,exit -F arch=b64 -S execve -F auid>=0 -F egid!=994 -F auid=-1 -F key=audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=0 -F egid!=994 -F auid=-1 -F key=audit-wazuh-c
EOF

    # Apply rules
    echo -e "${blue}[~] Reloading auditd rules...${nc}"
    if sudo service auditd restart; then
        echo -e "${green}[✓] Audit rules untuk Wazuh berhasil diterapkan.${nc}"
    else
        echo -e "${red}[X] Gagal reload auditd. Cek error-nya.${nc}"
        return 1
    fi

    # Verifikasi
    echo -e "${yellow}[*] Rules aktif saat ini:${nc}"
    sudo auditctl -l | grep audit-wazuh-c
}

set_timeout() {
echo -e "\033[1;34m===============================================\033[0m"
    echo -e "${yellow}[*] Memeriksa dan menambahkan konfigurasi timeout...${nc}"

    # Cek dan tambahkan konfigurasi timeout pada /etc/bash.bashrc
    echo -e "${yellow}[~] Memeriksa dan menambahkan konfigurasi timeout pada /etc/bash.bashrc...${nc}"
    if ! grep -q "TMOUT=600" /etc/bash.bashrc; then
        echo -e "${yellow}[~] Konfigurasi TMOUT belum ada, menambahkannya ke /etc/bash.bashrc...${nc}"
        sudo sh -c 'echo "TMOUT=600" >> /etc/bash.bashrc'
        sudo sh -c 'echo "export TMOUT" >> /etc/bash.bashrc'
    else
        echo -e "${green}[✓] Konfigurasi TMOUT sudah ada di /etc/bash.bashrc.${nc}"
    fi

    # Cek dan tambahkan konfigurasi timeout pada /etc/profile
    echo -e "${yellow}[~] Memeriksa dan menambahkan konfigurasi timeout pada /etc/profile...${nc}"
    if ! grep -q "TMOUT=600" /etc/profile; then
        echo -e "${yellow}[~] Konfigurasi TMOUT belum ada, menambahkannya ke /etc/profile...${nc}"
        sudo sh -c 'echo "TMOUT=600" >> /etc/profile'
        sudo sh -c 'echo "export TMOUT" >> /etc/profile'
    else
        echo -e "${green}[✓] Konfigurasi TMOUT sudah ada di /etc/profile.${nc}"
    fi

    echo -e "${green}[✓] Konfigurasi timeout selesai.${nc}"
}


# Fungsi untuk konfigurasi user account dan environment
user_account_env() {
    echo -e "${yellow}[*] Menyiapkan pengaturan untuk user account dan environment...${nc}"

    # Fungsi bantu untuk update atau tambahkan konfigurasi di /etc/login.defs
    update_login_defs_param() {
        local param="$1"
        local value="$2"
        if grep -q "^${param}" /etc/login.defs; then
            current_value=$(grep "^${param}" /etc/login.defs | awk '{print $2}')
            if [ "$current_value" != "$value" ]; then
                sudo sed -i "s/^${param}.*/${param} ${value}/" /etc/login.defs
                echo -e "${yellow}[~] Mengupdate ${param} menjadi ${value}${nc}"
            else
                echo -e "${green}[✓] ${param} sudah diset ke ${value}${nc}"
            fi
        else
            echo "${param} ${value}" | sudo tee -a /etc/login.defs > /dev/null
            echo -e "${yellow}[+] Menambahkan ${param}=${value} ke /etc/login.defs${nc}"
        fi
    }

    # Konfigurasi login.defs
    update_login_defs_param "PASS_MAX_DAYS" 90
    update_login_defs_param "PASS_MIN_DAYS" 7
    update_login_defs_param "PASS_WARN_AGE" 7
    update_login_defs_param "INACTIVE" 30

    # Fungsi bantu untuk atur umask di login.defs dan environment shell
    set_umask_if_missing() {
        local file="$1"

        if [[ "$file" == "/etc/login.defs" ]]; then
            if grep -Eq '^\s*UMASK\s+027' "$file"; then
                echo -e "${green}[✓] UMASK 027 sudah disetel dengan benar di ${file}${nc}"
            elif grep -Eq '^\s*UMASK\s+[0-9]{3}' "$file"; then
                sudo sed -i 's/^\s*UMASK\s\+[0-9]\{3\}/UMASK 027/' "$file"
                echo -e "${yellow}[~] Mengubah UMASK menjadi 027 di ${file}${nc}"
            else
                echo "UMASK 027" | sudo tee -a "$file" > /dev/null
                echo -e "${yellow}[+] Menambahkan UMASK 027 ke ${file}${nc}"
            fi
        else
            if grep -Eq '^\s*umask\s+027' "$file"; then
                echo -e "${green}[✓] umask 027 sudah ada di ${file}${nc}"
            else
                echo "umask 027" | sudo tee -a "$file" > /dev/null
                echo -e "${yellow}[+] Menambahkan umask 027 ke ${file}${nc}"
            fi
        fi
    }

    # Set umask di berbagai file
    set_umask_if_missing "/etc/login.defs"
   # set_umask_if_missing "/etc/bash.bashrc"
   # set_umask_if_missing "/etc/profile"

    # Cek dan set TMOUT
    if grep -q "^TMOUT=" /etc/profile; then
        sudo sed -i 's/^TMOUT=.*/TMOUT=600/' /etc/profile
        echo -e "${yellow}[~] Mengupdate TMOUT=600 di /etc/profile${nc}"
    else
        echo "TMOUT=600" | sudo tee -a /etc/profile > /dev/null
        echo -e "${yellow}[+] Menambahkan TMOUT=600 ke /etc/profile${nc}"
    fi

    echo -e "${green}[✓] Pengaturan untuk user account dan environment berhasil diterapkan.${nc}"
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

install_aide
sleep 2

setup_cron_aide
sleep 2

apply_process_harden
sleep 2

install_apparmor
sleep 2

disable_service
sleep 2

special_purpose_service
sleep 2

network_parameters
sleep 2

network_parameters_host
sleep 2

audit_legacy
sleep 2

ssh_config
sleep 2

audit_wazuh_agent
sleep 2

set_timeout
sleep 2

user_account_env
sleep 4

 # Pesan akhir
echo -e "\033[1;34m===============================================\033[0m"
    echo -e "${green}[*] Server berhasil terhardening dan konfigurasi selesai.${nc}"
    echo -e "${green}[✓] Semua langkah telah berhasil diterapkan.${nc}"
    echo -e "${green}[✓] Server siap untuk operasional dengan konfigurasi yang aman.${nc}"


}

main
