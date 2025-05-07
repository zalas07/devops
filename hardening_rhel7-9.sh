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
    log "$red" "Performing baseline configuration check..."
    sleep 1

    # 1. OS Check
    log "$blue" "==============================================="
    log "$yellow" "Checking Operating System Info..."

    log "$green" "Operating System Info:"
    [ -f /etc/redhat-release ] && cat /etc/redhat-release
    uname -a
    echo ""

    sleep 2

    # 2. System File Type
    log "$blue" "==============================================="
    log "$yellow" "Checking File System Types..."
    log "$green" "File System (df -T):"
    df -T | grep -v tmpfs
    echo ""
    sleep 2

    # 3. Directory listing under /var
    log "$blue" "==============================================="
    log "$yellow" "Directory listing under /var:"
    ls -l /var | grep "^d"
    echo ""
    sleep 2

    # 4. Directory listing under /home
    log "$blue" "==============================================="
    log "$yellow" "Directory listing under /home:"
    ls -l /home | grep "^d"
    echo ""
    sleep 2
}

software_update() {
    echo -e "${yellow}[*] Mengecek konfigurasi 'gpgcheck' di /etc/yum.conf...${nc}"

    if [ ! -f /etc/yum.conf ]; then
        echo -e "${red}[X] File /etc/yum.conf tidak ditemukan.${nc}"
        return 1
    fi

    # Jalankan grep dan simpan hasilnya
    result=$(grep -E "^\s*gpgcheck" /etc/yum.conf)

    if [ -n "$result" ]; then
        echo -e "${green}[✓] Ditemukan konfigurasi gpgcheck di /etc/yum.conf:${nc}"
        echo "$result"
    else
        echo -e "${red}[X] Tidak ditemukan konfigurasi gpgcheck di /etc/yum.conf.${nc}"
    fi
}

install_aide() {
    log "$blue" "============================================="
    log "$yellow" "Mengecek apakah paket AIDE sudah terinstall atau belum......"

    if ! rpm -q aide >/dev/null 2>&1; then
        log "$red" "Paket AIDE belum terpasang"
        log "$yellow" "Memulai instalasi...."

        # Gunakan yum atau dnf sesuai ketersediaan
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y aide
        else
            yum install -y aide
        fi

        if [ $? -eq 0 ]; then 
            log "$green" "AIDE berhasil diinstall!"
            
            log "$yellow" "Memulai konfigurasi AIDE..."

            aide_conf="/etc/aide.conf"
            install_location="/var/lib/aide"
            default_db="${install_location}/aide.db.gz"

            echo -n "Masukkan email atau URL laporan (misal: root@domain.com): "
            read domain_or_email

            log "$yellow" "Melakukan konfigurasi AIDE untuk domain/email: $domain_or_email"

            # Backup config lama
            cp "$aide_conf" "$aide_conf.bak"

            # Update lokasi database jika perlu
            sed -i "s|^database=file:.*|database=file:${default_db}|" "$aide_conf"
            sed -i "s|^database_out=file:.*|database_out=file:${install_location}/aide.db.new.gz|" "$aide_conf"

            # Tambahkan report_url jika belum ada
            if grep -q '^report_url=' "$aide_conf"; then
                sed -i "s|^report_url=.*|report_url=$domain_or_email|" "$aide_conf"
            else
                echo "report_url=$domain_or_email" >> "$aide_conf"
            fi

            # Inisialisasi database AIDE
            log "$blue" "Inisialisasi database AIDE..."
            aide --init

            if [ $? -eq 0 ]; then
                log "$green" "Database AIDE berhasil dibuat!"
                log "$yellow" "Memindahkan database ke lokasi aktif..."
                mv "${install_location}/aide.db.new.gz" "${default_db}"
                log "$green" "✅ AIDE siap digunakan!"
            else
                log "$red" "❌ Gagal inisialisasi AIDE!"
            fi
        else
            log "$red" "❌ Instalasi AIDE gagal. Periksa repositori atau koneksi!"
            return 1
        fi
    else
        log "$green" "✅ AIDE sudah terpasang"
        log "$blue" "Versi AIDE:"
        aide --version | head -n 1
    fi
}


setup_cron_aide() {
    log "$blue" "============================================="
    log "$yellow" "Mengecek Cron Job AIDE di crontab root..."

    aide_log_dir="/var/log/aide"
    aide_log_file="${aide_log_dir}/aide.log"

    # Pastikan direktori log ada
    if [ ! -d "$aide_log_dir" ]; then
        mkdir -p "$aide_log_dir"
        chown root:root "$aide_log_dir"
        chmod 750 "$aide_log_dir"
        log "$green" "Direktori $aide_log_dir berhasil dibuat."
    else
        log "$blue" "Direktori $aide_log_dir sudah ada."
    fi

    # Pastikan file log ada
    if [ ! -f "$aide_log_file" ]; then
        touch "$aide_log_file"
        chown root:root "$aide_log_file"
        chmod 640 "$aide_log_file"
        log "$green" "File log AIDE berhasil dibuat."
    else
        log "$blue" "File log AIDE sudah ada."
    fi

    sleep 1

    # Path default binary AIDE
    aide_bin="/usr/sbin/aide"
    cron_line="0 4 * * * $aide_bin --check > $aide_log_file 2>&1"

    # Cek dan tambahkan cron jika belum ada
    if crontab -l -u root 2>/dev/null | grep -q "aide --check"; then
        log "$green" "Cron Job AIDE sudah terpasang!"
    else
        log "$yellow" "Menambahkan Cron Job AIDE ke crontab root..."
        (crontab -l -u root 2>/dev/null; echo "$cron_line") | crontab -u root -
        log "$green" "Cron Job AIDE berhasil ditambahkan!"
    fi

    sleep 1
}

apply_process_harden() {
    local sysctl_file="/etc/sysctl.d/99-hardening.conf"

    log "$blue" "================================================="
    log "$yellow" "Menerapkan hardening pada fs.suid_dumpable dan ASLR..."

    # Tambahkan/replace parameter hardening
    mkdir -p /etc/sysctl.d

    echo "fs.suid_dumpable = 0" > "$sysctl_file"
    echo "kernel.randomize_va_space = 2" >> "$sysctl_file"

    # Terapkan konfigurasi
    sysctl --system > /dev/null 2>&1

    log "$green" "Parameter fs.suid_dumpable dan ASLR berhasil diterapkan melalui $sysctl_file."

    # Mengatur login banner
    log "$blue" "================================================="
    log "$yellow" "Mengatur login banner ke /etc/motd, /etc/issue, dan /etc/issue.net..."

    local banner="The System is for the use of BRI Authorized Users Only.
Individuals using this computer system without authority, or in excess of their authority,
are subject to having all of their activities on this system monitored and recorded by system personnel. in the course of monitoring Individuals improperly using this system or in the course of system maintenance, the activities of authorized users may also be monitored."

    echo "$banner" | tee /etc/motd /etc/issue /etc/issue.net > /dev/null

    log "$green" "Banner berhasil diterapkan."
    sleep 1
}

configure_selinux() {
    local mode="${1:-enforcing}"
    local policy="${2:-targeted}"
    local selinux_config="/etc/selinux/config"

    log "$blue" "================================================="
    log "$yellow" "Memastikan SELinux terpasang dan dikonfigurasi..."

    # Cek tools tersedia
    if ! command -v sestatus >/dev/null 2>&1; then
        log "$red" "SELinux tools belum tersedia. Menginstall..."

        if command -v dnf >/dev/null 2>&1; then
            dnf install -y libselinux-utils selinux-policy selinux-policy-targeted policycoreutils
        else
            yum install -y libselinux selinux-policy selinux-policy-targeted policycoreutils
        fi

        if [ $? -ne 0 ]; then
            log "$red" "Gagal menginstal SELinux. Periksa repo dan koneksi!"
            return 1
        fi
    else
        log "$green" "SELinux sudah terpasang."
    fi

    # Pastikan file konfigurasi ada
    if [ ! -f "$selinux_config" ]; then
        log "$red" "File $selinux_config tidak ditemukan. Membuat file kosong..."
        touch "$selinux_config"
    fi

    log "$blue" "Mengatur SELINUX=$mode dan SELINUXTYPE=$policy..."

    # Update konfigurasi SELinux
    sed -i "s/^SELINUX=.*/SELINUX=$mode/" "$selinux_config" 2>/dev/null || echo "SELINUX=$mode" >> "$selinux_config"
    sed -i "s/^SELINUXTYPE=.*/SELINUXTYPE=$policy/" "$selinux_config" 2>/dev/null || echo "SELINUXTYPE=$policy" >> "$selinux_config"

    log "$green" "SELinux dikonfigurasi ke: MODE=$mode, TYPE=$policy"
    log "$yellow" "Catatan: Reboot dibutuhkan agar perubahan SELinux aktif."

    sleep 1
}

disable_service() {
    log "$blue" "================================================="
    log "$yellow" "[*] Menonaktifkan service legacy yang tidak dibutuhkan..."

    local services=(
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
        log "$blue" "Memeriksa service: $service"

        # Coba deteksi dengan systemctl
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl list-units --type=service --all | grep -qw "${service}.service"; then
                systemctl stop "${service}.service" 2>/dev/null
                systemctl disable "${service}.service" 2>/dev/null
                log "$green" "Service $service dinonaktifkan via systemctl."
            else
                log "$blue" "Service $service tidak ditemukan via systemctl."
            fi

        # Jika systemctl tidak ada, pakai service + chkconfig
        elif command -v service >/dev/null 2>&1 && command -v chkconfig >/dev/null 2>&1; then
            if service "$service" status >/dev/null 2>&1 || netstat -tulpn | grep -qw "$service"; then
                service "$service" stop 2>/dev/null
                chkconfig "$service" off 2>/dev/null
                rm -f "/etc/xinetd.d/$service" 2>/dev/null
                log "$green" "Service $service dinonaktifkan via service/chkconfig."
            else
                log "$blue" "Service $service tidak aktif atau tidak ditemukan."
            fi
        else
            log "$red" "Tidak bisa mendeteksi metode manajemen service."
        fi

        echo
    done

    log "$green" "[+] Selesai menonaktifkan semua target service."
    sleep 2
}

special_purpose_service() {
    log "$blue" "===================================================="
    log "$yellow" "[*] Menjalankan Special Purpose Services secara kompatibel..."

    # Helper stop/disable service
    stop_disable_service() {
        local svc="$1"
        if command -v systemctl &>/dev/null; then
            systemctl stop "$svc" 2>/dev/null
            systemctl disable "$svc" 2>/dev/null
        elif command -v service &>/dev/null && command -v chkconfig &>/dev/null; then
            service "$svc" stop 2>/dev/null
            chkconfig "$svc" off 2>/dev/null
        fi
    }

    # 1. NTP
    log "$yellow" "[*] Mengecek dan mengonfigurasi NTP..."
    if ! rpm -q ntp >/dev/null 2>&1; then
        log "$blue" "[i] NTP belum terinstall. Menginstall..."
        yum install -y ntp
    fi

    if [ -f /etc/ntp.conf ]; then
        sed -i '/^server /d' /etc/ntp.conf
        echo "server 172.18.104.166" >> /etc/ntp.conf

        if command -v systemctl &>/dev/null; then
            systemctl restart ntpd
            systemctl enable ntpd
        else
            service ntpd restart
            chkconfig ntpd on
        fi

        sleep 2
        log "$yellow" "[~] Mengecek koneksi ke NTP Server..."
        if command -v ntpq &>/dev/null; then
            output=$(ntpq -p | grep "172.18.104.166")
            if [[ -n "$output" ]]; then
                log "$green" "NTP terkoneksi ke server 172.18.104.166:\n$output"
            else
                log "$red" "NTP tidak dapat terkoneksi ke server 172.18.104.166."
            fi
        else
            log "$red" "Perintah ntpq tidak tersedia."
        fi
    fi

    # 2. Postfix (localhost only)
    log "$yellow" "[*] Mengecek dan mengonfigurasi Postfix..."
    if ! rpm -q postfix >/dev/null 2>&1; then
        log "$yellow" "[~] Menginstall Postfix..."
        yum install -y postfix
    fi

    if [ -f /etc/postfix/main.cf ]; then
        sed -i 's/^inet_interfaces = .*/inet_interfaces = loopback-only/' /etc/postfix/main.cf

        if command -v systemctl &>/dev/null; then
            systemctl restart postfix
            systemctl enable postfix
        else
            service postfix restart
            chkconfig postfix on
        fi

        log "$green" "Postfix diatur hanya untuk localhost."
    fi

    # 3. SNMPD
    log "$yellow" "[*] Mengecek dan mengonfigurasi SNMPD..."
    if ! rpm -q net-snmp >/dev/null 2>&1; then
        yum install -y net-snmp net-snmp-utils
    fi

    if command -v systemctl &>/dev/null; then
        systemctl restart snmpd
        systemctl enable snmpd
    else
        service snmpd restart
        chkconfig snmpd on
    fi

    log "$green" "SNMPD Diaktifkan."

    # 4. Disable Special Purpose Services
    log "$yellow" "[*] Menonaktifkan service yang tidak diperlukan..."
    disable_services=(
        xorg-x11
        avahi-daemon
        cups
        dhcpd
        openldap-servers
        nfs-utils
        rpcbind
        named
        vsftpd
        httpd
        dovecot
        samba
        squid
        net-snmp
        exim
    )

    for svc in "${disable_services[@]}"; do
        if rpm -q "$svc" >/dev/null 2>&1; then
            stop_disable_service "$svc"
            log "$green" "Service $svc dinonaktifkan."
        fi
    done

    log "$green" "Module Special Purpose Service selesai."
}

network_parameters_host_rhel7_9() {
    echo -e "${blue}=============================================="
    echo -e "${yellow}[*] Menetapkan Parameter keamanan jaringan di /etc/sysctl.conf...${nc}"

    # Periksa apakah file konfigurasi sysctl custom sudah ada
    SYSCTL_CUSTOM_FILE="/etc/sysctl.d/99-hardening.conf"
    touch "$SYSCTL_CUSTOM_FILE"

    # Daftar parameter yang ingin di-set
    declare -A params=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="0"
        ["net.ipv4.conf.default.secure_redirects"]="0"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
    )

    # Tambahkan parameter hanya jika tersedia di sysctl
    for param in "${!params[@]}"; do
        value="${params[$param]}"
        if sysctl -a 2>/dev/null | grep -q "^$param"; then
            if grep -q "^$param" "$SYSCTL_CUSTOM_FILE"; then
                sed -i "s|^$param.*|$param = $value|" "$SYSCTL_CUSTOM_FILE"
                echo -e "${yellow}[~] $param diperbarui ke $value.${nc}"
            else
                echo "$param = $value" >> "$SYSCTL_CUSTOM_FILE"
                echo -e "${cyan}[+] $param ditambahkan ke $value.${nc}"
            fi
        else
            echo -e "${red}[X] $param tidak dikenal oleh sysctl. Dilewati.${nc}"
        fi
    done

    # Cek jika bridge module masih berlaku
    if modprobe -nq br_netfilter; then
        echo -e "${yellow}[~] Memuat modul br_netfilter...${nc}"
        modprobe br_netfilter
        cat <<EOF >> "$SYSCTL_CUSTOM_FILE"
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
EOF
    else
        echo -e "${red}[X] br_netfilter tidak tersedia, parameter bridge dilewati.${nc}"
    fi

    # Terapkan semua konfigurasi
    sysctl --system > /dev/null && echo -e "${green}[✓] Semua parameter sysctl berhasil diterapkan.${nc}"
}

audit() {
    echo -e "[*] Memulai konfigurasi auditd dan rsyslog..."

    # Deteksi package manager
    if command -v dnf &> /dev/null; then
        pkg_mgr="dnf"
    elif command -v yum &> /dev/null; then
        pkg_mgr="yum"
    elif command -v apt &> /dev/null; then
        pkg_mgr="apt"
    else
        echo -e "[X] Package manager tidak dikenali. Instalasi dibatalkan."
        return 1
    fi

    echo -e "[~] Memeriksa dan menginstal auditd & rsyslog jika diperlukan..."
    $pkg_mgr install -y auditd rsyslog

    echo -e "[✓] Instalasi auditd dan rsyslog selesai."

    mkdir -p /etc/audit/rules.d

    # ===== Membuat audit.rules dasar jika belum ada =====
    if [ ! -f /etc/audit/audit.rules ]; then
        cat << 'EOF' > /etc/audit/audit.rules
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
    fi

    # ===== Tambahan aturan audit jika belum ada =====
    declare -A audit_rules_files=(
        [50-logins.rules]="#login and logout are collected
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins"
        [50-delete.rules]="#file deletion events by users are collected
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=500 -F auid!=4294967295 -k delete"
        [50-scope.rules]="#change to system administration scope(sudoers) is collected
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope"
        [50-session.rules]="#session initiation information is collected
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins"
    )

    for rule_file in "${!audit_rules_files[@]}"; do
        path="/etc/audit/rules.d/$rule_file"
        if [ ! -f "$path" ]; then
            echo -e "[~] Membuat $path..."
            echo "${audit_rules_files[$rule_file]}" > "$path"
        else
            echo -e "[✓] File $path sudah ada."
        fi
    done

    # ===== Konfigurasi auditd.conf =====
    sed -i 's/^max_log_file *=.*/max_log_file = 200/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file_action *=.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    echo -e "[✓] Konfigurasi auditd.conf selesai."

    # ===== Aktifkan dan jalankan service =====
    if command -v systemctl &> /dev/null; then
        systemctl enable --now auditd
        systemctl enable --now rsyslog
    else
        service auditd start
        service rsyslog start
        chkconfig auditd on
        chkconfig rsyslog on
    fi

    echo -e "[✓] Konfigurasi dasar auditd dan rsyslog selesai."
}

ssh_config() {
    echo "🛠️  Starting SSH configuration hardening..."

    SSH_CONFIG="/etc/ssh/sshd_config"

    # Backup sebelum ubah
    if [ -f "$SSH_CONFIG" ] && [ ! -f "${SSH_CONFIG}.bak" ]; then
        cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"
        echo "✅ Backup created: ${SSH_CONFIG}.bak"
    fi

    # Pastikan permission 600
    chmod 600 "$SSH_CONFIG"
    echo "✅ Set permissions 600 on $SSH_CONFIG"

    # Fungsi update/append
    update_or_append() {
        local key="$1"
        local value="$2"
        if grep -qE "^\s*${key}\s+" "$SSH_CONFIG"; then
            sed -i "s|^\s*${key}\s\+.*|${key} ${value}|g" "$SSH_CONFIG"
        else
            echo "${key} ${value}" >> "$SSH_CONFIG"
        fi
    }

    # Cek versi sshd
    if command -v sshd >/dev/null 2>&1; then
        SSH_VER=$(sshd -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | cut -d_ -f2)
        echo "ℹ️  Detected OpenSSH version: $SSH_VER"
    else
        echo "⚠️  sshd not found, skipping version-dependent settings."
        SSH_VER="unknown"
    fi

    # Konfigurasi utama
    update_or_append "Protocol" "2"
    update_or_append "LogLevel" "INFO"
    update_or_append "X11Forwarding" "no"
    update_or_append "MaxAuthTries" "4"
    update_or_append "IgnoreRhosts" "yes"
    update_or_append "HostbasedAuthentication" "no"
    update_or_append "PermitRootLogin" "no"
    update_or_append "PermitEmptyPasswords" "no"
    update_or_append "PermitUserEnvironment" "no"
    update_or_append "ClientAliveInterval" "300"
    update_or_append "ClientAliveCountMax" "0"
    update_or_append "LoginGraceTime" "60"

    # MACs (OpenSSH >= 6.6)
    if [[ "$SSH_VER" =~ ^[0-9]+\.[0-9]+$ ]]; then
        ver_check=$(echo "$SSH_VER >= 6.6" | bc)
        if [ "$ver_check" -eq 1 ]; then
            update_or_append "MACs" "hmac-sha2-512,hmac-sha2-256"
            echo "✅ MACs updated with SHA2 algorithms."
        else
            echo "⚠️  Skipping MACs config: not supported in OpenSSH $SSH_VER"
        fi
    fi

    echo "✅ SSH baseline configuration applied."

    # Restart service SSH (systemd > service > fallback)
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
        systemctl enable sshd 2>/dev/null || systemctl enable ssh
        echo "✅ SSH service restarted and enabled via systemctl."
    elif command -v service >/dev/null 2>&1; then
        service sshd restart 2>/dev/null || service ssh restart
        chkconfig sshd on 2>/dev/null || chkconfig ssh on 2>/dev/null
        echo "✅ SSH service restarted and enabled via service/chkconfig."
    else
        echo "⚠️  Could not restart SSH: no systemctl or service found."
    fi
}

user_account_env() {
    echo -e "${yellow}[*] Menyiapkan pengaturan untuk user account dan environment...${nc}"

    # Fungsi bantu untuk set atau update parameter di /etc/login.defs
    set_login_defs_param() {
        local param="$1"
        local value="$2"
        if grep -qE "^$param" /etc/login.defs; then
            if grep -qE "^$param\s+$value" /etc/login.defs; then
                echo "[=] $param sudah di-set ke $value"
            else
                sed -i "s/^$param.*/$param $value/" /etc/login.defs
                echo "[~] $param diperbarui ke $value"
            fi
        else
            echo "$param $value" >> /etc/login.defs
            echo "[+] $param ditambahkan dengan nilai $value"
        fi
    }

    # Set kebijakan password expiration
    set_login_defs_param "PASS_MAX_DAYS" 90
    set_login_defs_param "PASS_MIN_DAYS" 7
    set_login_defs_param "PASS_WARN_AGE" 7
    set_login_defs_param "INACTIVE" 30

    # Set umask default ke 027 di /etc/bashrc dan /etc/profile
    for file in /etc/bashrc /etc/profile; do
        if ! grep -q "^umask 027" "$file"; then
            echo "umask 027" >> "$file"
            echo "[+] umask 027 ditambahkan ke $file"
        else
            echo "[=] umask 027 sudah ada di $file"
        fi
    done

    # Set TMOUT (shell timeout) di /etc/profile.d/tmout.sh biar lebih modular
    mkdir -p /etc/profile.d
    tmout_file="/etc/profile.d/tmout.sh"
    echo "TMOUT=600" > "$tmout_file"
    echo "readonly TMOUT" >> "$tmout_file"
    echo "export TMOUT" >> "$tmout_file"
    echo "[+] TMOUT=600 diset secara permanen di $tmout_file"

    echo -e "${green}[✓] Pengaturan user account dan environment untuk RHEL 7–9 berhasil diterapkan.${nc}"
}

audit_wazuh_agent() {
    echo "🛠️  Menambahkan audit rules untuk Wazuh Agent..."

    rules_dir="/etc/audit/rules.d"
    wazuh_rules_file="$rules_dir/wazuh.rules"

    # Cek apakah auditd tersedia
    if ! command -v auditctl &>/dev/null || ! pidof auditd &>/dev/null; then
        echo "❌ auditd tidak ditemukan atau tidak aktif. Silakan install dan aktifkan auditd."
        return 1
    fi

    # Cek apakah direktori rules.d tersedia
    if [ ! -d "$rules_dir" ]; then
        echo "❌ Direktori $rules_dir tidak ditemukan. Membuat direktori..."
        mkdir -p "$rules_dir" || {
            echo "❌ Gagal membuat direktori $rules_dir."
            return 1
        }
    fi

    # Backup file lama jika ada
    if [ -f "$wazuh_rules_file" ]; then
        backup_file="${wazuh_rules_file}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$wazuh_rules_file" "$backup_file"
        echo "📦 Backup rules lama: $backup_file"
    fi

    echo "✏️  Menulis ulang file $wazuh_rules_file ..."
    tee "$wazuh_rules_file" > /dev/null <<EOF
-a always,exit -F arch=b64 -S execve -F auid>=0 -F auid!=4294967295 -F egid!=994 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=0 -F auid!=4294967295 -F egid!=994 -k audit-wazuh-c
EOF

    # Reload auditd rules
    echo "🔄 Reloading auditd rules..."

    if command -v augenrules &>/dev/null; then
        augenrules --load
    fi

    if systemctl is-active --quiet auditd; then
        systemctl restart auditd
    elif service auditd status &>/dev/null; then
        service auditd restart
    else
        echo "⚠️  Tidak bisa me-restart auditd. Coba restart manual."
        return 1
    fi

    echo "✅ Audit rules untuk Wazuh berhasil diterapkan."
    echo "🔍 Rules aktif:"
    auditctl -l | grep audit-wazuh-c || echo "⚠️  Tidak ditemukan rule aktif dengan key audit-wazuh-c"
}

set_timeout() {
    echo "🕒 Memeriksa dan menambahkan konfigurasi shell timeout..."

    files_to_check=("/etc/profile" "/etc/bash.bashrc" "/etc/bashrc") # Dukungan multi-distro

    for file in "${files_to_check[@]}"; do
        if [ -f "$file" ]; then
            if grep -q "^TMOUT=" "$file"; then
                echo "🔁 TMOUT sudah ada di $file, akan diperbarui ke nilai 600..."
                sudo sed -i 's/^TMOUT=.*/TMOUT=600/' "$file"
                if ! grep -q "^export TMOUT" "$file"; then
                    echo "export TMOUT" | sudo tee -a "$file" > /dev/null
                fi
            else
                echo "➕ Menambahkan TMOUT=600 dan export ke $file"
                {
                    echo "TMOUT=600"
                    echo "export TMOUT"
                } | sudo tee -a "$file" > /dev/null
            fi
        fi
    done

    echo "✅ Konfigurasi shell timeout selesai. Timeout akan aktif saat sesi shell dimulai ulang."
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
Compatible: Red Hat Enterprice 5 & 6

EOF
echo -e "${nc}"
sleep 2

baseline_check
sleep 2

software_update
sleep 2

install_aide
sleep 2

setup_cron_aide
sleep 2

apply_process_harden
sleep 2

configure_selinux
sleep 2

disable_service_rhel
sleep 2

special_purpose_service_rhel
sleep 2

network_parameters_host
sleep 2

audit
sleep 2

ssh_config
sleep 2

audit_wazuh_agent
sleep 2

set_timeout
sleep 2

user_account_env
sleep 2

 # Pesan akhir
    echo -e "${green}[*] Server berhasil terhardening dan konfigurasi selesai.${nc}"
    echo -e "${green}[✓] Semua langkah telah berhasil diterapkan.${nc}"
    echo -e "${green}[✓] Server siap untuk operasional dengan konfigurasi yang aman.${nc}"


}

main




