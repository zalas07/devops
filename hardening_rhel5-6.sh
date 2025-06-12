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
        
        yum install -y aide
        
        if [ $? -eq 0 ]; then 
            log "$green" "AIDE Berhasil diinstall!"
            
            log "$yellow" "Memulai konfigurasi AIDE..."

            # Lokasi default database dan konfigurasi di RHEL
            aide_conf="/etc/aide.conf"
            default_db="/var/lib/aide/aide.db.gz"

            echo -n "Masukkan lokasi instalasi AIDE (misalnya /usr/local/aide): "
            read install_location
            echo -n "Masukkan domain atau email: "
            read domain_or_email

            log "$yellow" "Proses konfigurasi untuk AIDE dengan lokasi $install_location dan domain/email $domain_or_email"

            # Backup konfigurasi lama
            cp "$aide_conf" "$aide_conf.bak"

            # Ubah lokasi database
            sed -i "s|^database=file:.*|database=file:$install_location/aide.db.gz|" "$aide_conf"
            sed -i "s|^database_out=file:.*|database_out=file:$install_location/aide.db.new.gz|" "$aide_conf"

            # Tambah info report (jika ada baris report_url, kalau gak ada bisa disisipkan)
            if grep -q '^report_url=' "$aide_conf"; then
                sed -i "s|^report_url=.*|report_url=$domain_or_email|" "$aide_conf"
            else
                echo "report_url=$domain_or_email" >> "$aide_conf"
            fi

            # Inisialisasi database AIDE
            aide --init

            if [ $? -eq 0 ]; then
                log "$green" "Database AIDE berhasil dibuat!"
                log "$yellow" "Pindahkan database ke lokasi aktif..."
                mv /var/lib/aide/aide.db.new.gz "$install_location/aide.db.gz"
                log "$green" "AIDE siap digunakan!"
            else
                log "$red" "Gagal inisialisasi AIDE!"
            fi
        else
            log "$red" "AIDE gagal diinstall. Periksa repositori dan koneksi!"
            return 1
        fi
    else
        log "$green" "AIDE sudah terpasang"
        log "$blue" "Versi AIDE:"
        aide --version | head -n 1
    fi
}

setup_cron_aide() {

    log "$yellow" "Mengecek Cron Job AIDE di crontab root......"

    # Direktori log AIDE
    if [ ! -d /var/log/aide ]; then
        mkdir -p /var/log/aide
        chown root:root /var/log/aide
        chmod 750 /var/log/aide
        log "$green" "Direktori /var/log/aide berhasil dibuat."
    else
        log "$blue" "Direktori /var/log/aide sudah ada."
    fi

    # File log aide.log
    if [ ! -f /var/log/aide/aide.log ]; then
        touch /var/log/aide/aide.log
        chown root:root /var/log/aide/aide.log
        chmod 640 /var/log/aide/aide.log
        log "$green" "File log AIDE berhasil dibuat."
    else
        log "$blue" "File log AIDE sudah ada."
    fi

    sleep 2

    # Path AIDE default di RHEL 5/6 biasanya di /usr/sbin/aide
    cron_line="0 4 * * * /usr/sbin/aide --check > /var/log/aide/aide.log 2>&1"

    # Cek dan tambah cron ke crontab root
    crontab -l -u root 2>/dev/null | grep -q "aide --check"
    if [ $? -eq 0 ]; then
        log "$green" "Cron Job AIDE sudah terpasang!"
    else
        log "$blue" "Menambahkan Cron Job AIDE ke crontab root..."
        (crontab -l -u root 2>/dev/null; echo "$cron_line") | crontab -u root -
        log "$green" "Cron Job AIDE berhasil ditambahkan!"
    fi

    sleep 2
}

apply_process_harden() {

    local sysctl_conf="/etc/sysctl.conf"
    log "$blue" "================================================="
    log "$yellow" "Menambahkan parameter fs.suid_dumpable dan ASLR..."

    # Konfigurasi fs.suid_dumpable
    if grep -q "^fs.suid_dumpable" "$sysctl_conf"; then
        sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/' "$sysctl_conf"
    else
        echo "fs.suid_dumpable = 0" >> "$sysctl_conf"
    fi
    sleep 1

    # Konfigurasi ASLR
    if grep -q "^kernel.randomize_va_space" "$sysctl_conf"; then
        sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' "$sysctl_conf"
    else
        echo "kernel.randomize_va_space = 2" >> "$sysctl_conf"
    fi
    sleep 1

    # Terapkan konfigurasi sysctl
    /sbin/sysctl -p > /dev/null 2>&1

    log "$green" "Parameter fs.suid_dumpable dan ASLR berhasil diterapkan."

    # Set login banner
    log "$blue" "================================================="
    log "$yellow" "Mengatur banner login /etc/motd, /etc/issue, dan /etc/issue.net..."

    local banner="The System is for the use of BRI Authorized Users Only.
Individuals using this computer system without authority, or in excess of their authority,
are subject to having all of their activities on this system monitored and recorded by system personnel. in the course of monitoring Individuals improperly using this system or in the course of system maintenance, the activities of authorized users may also be monitored."


    echo "$banner" > /etc/motd
    echo "$banner" > /etc/issue
    echo "$banner" > /etc/issue.net

    log "$green" "Banner berhasil diterapkan ke motd, issue, dan issue.net."

    sleep 1
}

configure_selinux() {

    local selinux_config="/etc/selinux/config"

    log "$blue" "================================================="
    log "$yellow" "Mengecek dan memasang SELinux jika belum tersedia..."

    # Cek apakah SELinux tools tersedia
    if ! command -v sestatus >/dev/null 2>&1; then
        log "$red" "SELinux belum terpasang. Menginstall paket yang dibutuhkan..."

        yum install -y libselinux selinux-policy selinux-policy-targeted policycoreutils

        if [ $? -ne 0 ]; then
            log "$red" "Gagal menginstal SELinux. Pastikan repositori aktif dan terhubung ke internet!"
            return 1
        fi
    else
        log "$green" "SELinux sudah terpasang!"
    fi

    # Pastikan file konfigurasi ada
    if [ ! -f "$selinux_config" ]; then
        log "$red" "File $selinux_config tidak ditemukan. Membuat file konfigurasi baru..."
        touch "$selinux_config"
    fi

    log "$blue" "Mengatur SELINUX=enforcing dan SELINUXTYPE=targeted..."

    # Set SELINUX mode
    if grep -q "^SELINUX=" "$selinux_config"; then
        sed -i 's/^SELINUX=.*/SELINUX=enforcing/' "$selinux_config"
    else
        echo "SELINUX=enforcing" >> "$selinux_config"
    fi

    # Set policy type
    if grep -q "^SELINUXTYPE=" "$selinux_config"; then
        sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' "$selinux_config"
    else
        echo "SELINUXTYPE=targeted" >> "$selinux_config"
    fi

    log "$green" "Konfigurasi SELinux berhasil diterapkan!"
    log "$yellow" "Catatan: Sistem perlu direboot agar SELinux enforcing aktif."

    sleep 2
}

disable_service_rhel() {
    log "$blue" "================================================="
    log "$yellow" "[*] Menonaktifkan service legacy yang tidak dibutuhkan untuk RHEL 5/6..."

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

        # Cek status service dengan 'service --status-all' tidak tersedia, maka pakai cara manual
        if service "$service" status >/dev/null 2>&1 || netstat -tulpn | grep -q "$service"; then
            echo -e " Service $service AKTIF atau port terbuka, mencoba nonaktifkan..."

            # Stop service
            service "$service" stop 2>/dev/null

            # Disable saat boot
            chkconfig "$service" off 2>/dev/null

            # Hapus jika via xinetd
            rm -f "/etc/xinetd.d/$service" 2>/dev/null

            echo -e " Service $service berhasil dinonaktifkan."
        else
            echo -e " Service $service tidak aktif atau tidak ditemukan."
        fi

        echo
    done

    echo -e "${green}[+] Selesai memproses semua service yang ditargetkan.${nc}"
    sleep 2
}


special_purpose_service_rhel() {
    log "$blue" "===================================================="
    log "$yellow" "[*] Menjalankan Special Purpose Services untuk RHEL 5/6...${nc}"

    # 1. Konfigurasi & Aktivasi NTP
    echo -e "${yellow}[*] Mengecek dan mengonfigurasi NTP...${nc}"

    if ! rpm -q ntp >/dev/null 2>&1; then
        echo -e "${blue}[i] NTP belum terinstall. Menginstall...${nc}"
        yum install -y ntp
    fi

    if [ -f /etc/ntp.conf ]; then
        sed -i '/^server /d' /etc/ntp.conf
        echo "server 172.18.104.166" >> /etc/ntp.conf
        service ntpd restart
        chkconfig ntpd on
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
    fi

    # 2. Konfigurasi Postfix hanya untuk lokal
    echo -e "${yellow}[*] Mengecek dan mengonfigurasi Postfix...${nc}"
    if ! rpm -q postfix >/dev/null 2>&1; then
        echo -e "${yellow}[~] Menginstall Postfix...${nc}"
        yum install -y postfix
    fi

    if [ -f /etc/postfix/main.cf ]; then
        sed -i 's/^inet_interfaces = .*/inet_interfaces = loopback-only/' /etc/postfix/main.cf
        service postfix restart
        chkconfig postfix on
        echo -e "${green} Postfix diatur hanya untuk localhost.${nc}"
    fi

    # 3. Konfigurasi SNMPD
    echo -e "${yellow}[*] Mengecek dan mengonfigurasi SNMPD...${nc}"
    if ! rpm -q net-snmp >/dev/null 2>&1; then
        yum install -y net-snmp net-snmp-utils
    fi
    service snmpd restart
    chkconfig snmpd on
    echo -e "${green} SNMPD Diaktifkan.${nc}"

    # 4. Disable Service yang tidak perlu
    disable_services=(
        xorg-x11
        avahi
        cups
        dhcpd
        openldap-servers
        nfs-utils
        rpcbind
        bind
        vsftpd
        httpd
        dovecot
        samba
        squid
        net-snmp
        exim
    )
    echo -e "${yellow}[*] Menonaktifkan service yang tidak diperlukan...${nc}"

    for svc in "${disable_services[@]}"; do
        if rpm -q "$svc" >/dev/null 2>&1; then
            service "$svc" stop 2>/dev/null
            chkconfig "$svc" off 2>/dev/null
            echo -e "${green} Service $svc dinonaktifkan.${nc}"
        fi
    done

    echo -e "${green} Module Purpose Special service selesai.${nc}"
}

network_parameters_host() {
    echo -e "${blue}=============================================="
    echo -e "${yellow}[*] Menetapkan Parameter keamanan jaringan...${nc}"

    # Path fallback: gunakan /etc/sysctl.conf untuk RHEL 5/6 yang belum pakai sysctl.d
    local sysctl_conf="/etc/sysctl.conf"
    [[ -d /etc/sysctl.d ]] && sysctl_conf="/etc/sysctl.d/99-hardening.conf"

    echo -e "${cyan}[i] Menggunakan file konfigurasi: $sysctl_conf${nc}"

    # Backup sebelum edit
    [[ -f "$sysctl_conf" ]] && cp "$sysctl_conf" "${sysctl_conf}.bak_$(date +%F_%T)"

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
        ["net.bridge.bridge-nf-call-ip6tables"]="0"
        ["net.bridge.bridge-nf-call-iptables"]="0"
    )

    # Cek apakah br_netfilter tersedia
    if ! modprobe br_netfilter 2>/dev/null && ! lsmod | grep -q br_netfilter; then
        echo -e "${blue}[i] br_netfilter tidak tersedia. Melewati parameter bridge.*${nc}"
        unset params["net.bridge.bridge-nf-call-ip6tables"]
        unset params["net.bridge.bridge-nf-call-iptables"]
    fi

    # Proses tiap parameter
    for param in "${!params[@]}"; do
        value="${params[$param]}"
        sysctl_path="/proc/sys/${param//./\/}"

        if [[ -f "$sysctl_path" ]]; then
            # Gunakan sed jika param sudah ada
            if grep -qE "^$param\s*=" "$sysctl_conf"; then
                sed -i "s|^$param\s*=.*|$param = $value|" "$sysctl_conf"
                echo -e "${yellow}[~] Memperbarui $param ke $value.${nc}"
            else
                echo "$param = $value" >> "$sysctl_conf"
                echo -e "${cyan}[+] Menambahkan $param = $value.${nc}"
            fi
        else
            echo -e "${blue}[i] Melewati $param: tidak ditemukan di /proc/sys (tidak valid di kernel ini).${nc}"
        fi
    done

    # Terapkan perubahan
    if command -v sysctl >/dev/null; then
        if sysctl -p "$sysctl_conf" >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1; then
            echo -e "${green}[✓] Semua parameter sysctl berhasil diterapkan.${nc}"
        else
            echo -e "${red}[X] Beberapa parameter gagal diterapkan. Cek manual dengan 'sysctl -p'.${nc}"
        fi
    else
        echo -e "${red}[X] Perintah 'sysctl' tidak ditemukan di sistem ini.${nc}"
    fi
}

audit() {
    echo -e "[*] Memulai konfigurasi auditd dan rsyslog..."

    # Instalasi jika belum ada
    echo -e "[~] Memeriksa dan menginstall auditd & rsyslog jika diperlukan..."
    yum install -y audit rsyslog
    echo -e "[✓] Instalasi auditd dan rsyslog selesai."

    # Siapkan lokasi rules sementara
    TMP_RULES="/tmp/audit.rules"
    echo -e "[~] Membuat rules audit secara dinamis berdasarkan syscall yang tersedia..."

    # Awal rules
    cat << EOF > "$TMP_RULES"
-D
-b 8192
-f 1
EOF

    # Helper: hanya tambahkan rule kalau syscall tersedia
    add_syscall_rule() {
        local arch=$1
        local key=$2
        shift 2
        for syscall in "$@"; do
            if ausyscall --dump | awk '{print $2}' | grep -qw "$syscall"; then
                echo "-a always,exit -F arch=$arch -S $syscall -k $key" >> "$TMP_RULES"
            fi
        done
    }

    # Waktu & jam
    add_syscall_rule b64 time-change adjtimex settimeofday
    add_syscall_rule b32 time-change adjtimex settimeofday stime

    echo "-w /etc/localtime -p wa -k time-change" >> "$TMP_RULES"

    # Login dan logout
    echo "-w /var/log/lastlog -p wa -k logins" >> "$TMP_RULES"
    echo "-w /var/run/faillock/ -p wa -k logins" >> "$TMP_RULES"

    # Penghapusan file oleh user (pakai format benar)
    add_syscall_rule b64 delete unlink unlinkat rename renameat
    add_syscall_rule b32 delete unlink unlinkat rename renameat
    
    #-a always,exit -F arch=b64 -S unlink,rename -k delete
    #-a always,exit -F arch=b32 -S unlink,rename -k delete
    #echo "-F auid>=500 -F auid!=4294967295" >> "$TMP_RULES"

    # Akses sudoers
    echo "-w /etc/sudoers -p wa -k scope" >> "$TMP_RULES"
    echo "-w /etc/sudoers.d/ -p wa -k scope" >> "$TMP_RULES"

    # Sesi login user
    echo "-w /var/run/utmp -p wa -k session" >> "$TMP_RULES"
    echo "-w /var/log/wtmp -p wa -k logins" >> "$TMP_RULES"
    echo "-w /var/log/btmp -p wa -k logins" >> "$TMP_RULES"

    # Rules tambahan untuk Wazuh Agent
    add_syscall_rule b64 audit-wazuh-c execve
    add_syscall_rule b32 audit-wazuh-c execve

    # Pindahkan ke lokasi final
    cp "$TMP_RULES" /etc/audit/audit.rules
    rm -f "$TMP_RULES"
    echo -e "[✓] Konfigurasi /etc/audit/audit.rules selesai."

    # Konfigurasi auditd.conf
    echo -e "[~] Mengatur parameter log di /etc/audit/auditd.conf..."
    sed -i 's/^max_log_file =.*/max_log_file = 200/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sed -i 's/^space_left =.*/space_left = 90/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left =.*/admin_space_left = 80/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left_action =.*/admin_space_left_action = ROTATE/' /etc/audit/auditd.conf
    echo -e "[✓] Konfigurasi /etc/audit/auditd.conf selesai."

    # Aktifkan service
    echo -e "[*] Mengaktifkan dan memulai service auditd dan rsyslog..."
    service auditd start
    service rsyslog start
    chkconfig auditd on
    chkconfig rsyslog on
    echo -e "[✓] Konfigurasi dasar auditd dan rsyslog selesai."
}



ssh_config() {
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

    # Fungsi update atau append konfigurasi
    update_or_append() {
        local key="$1"
        local value="$2"
        if grep -qE "^\s*${key}\s+" "$SSH_CONFIG"; then
            sed -i "s|^\s*${key}\s\+.*|${key} ${value}|g" "$SSH_CONFIG"
        else
            echo "${key} ${value}" >> "$SSH_CONFIG"
        fi
    }

    # Dapatkan versi OpenSSH
    SSH_VER=$(sshd -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | cut -d_ -f2)
    echo "ℹ️  Detected OpenSSH version: $SSH_VER"

    update_or_append "Protocol" "2"
    update_or_append "LogLevel" "INFO"
    update_or_append "X11Forwarding" "no"
    update_or_append "MaxAuthTries" "4"
    update_or_append "IgnoreRhosts" "yes"
    update_or_append "HostbasedAuthentication" "no"
    update_or_append "PermitRootLogin" "no"
    update_or_append "PermitEmptyPasswords" "no"
    update_or_append "PermitUserEnvironment" "no"

    # Cek dukungan MACs
    if [[ $(echo "$SSH_VER >= 6.6" | bc) -eq 1 ]]; then
        update_or_append "MACs" "hmac-sha2-512,hmac-sha2-256"
        echo "✅ MACs updated with SHA2 algorithms."
    else
        echo "⚠️  Skipping MACs config: not supported in OpenSSH $SSH_VER"
    fi

    update_or_append "ClientAliveInterval" "300"
    update_or_append "ClientAliveCountMax" "0"
    update_or_append "LoginGraceTime" "60"

    echo "✅ SSH baseline configuration applied."

    # Restart SSH service
    if service sshd status > /dev/null 2>&1; then
        service sshd restart
        echo "✅ SSH service restarted."
    elif service ssh status > /dev/null 2>&1; then
        service ssh restart
        echo "✅ SSH service restarted."
    else
        echo "⚠️  SSH service not found or not active."
    fi

    # Enable on boot
    chkconfig sshd on 2>/dev/null
    chkconfig ssh on 2>/dev/null
    echo "✅ SSH service enabled on boot."
}


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
            echo -e "${yellow}[+] Menambahkan ${param} ${value} ke /etc/login.defs${nc}"
        fi
    }

    # Konfigurasi login.defs
    update_login_defs_param "PASS_MAX_DAYS" 90
    update_login_defs_param "PASS_MIN_DAYS" 7
    update_login_defs_param "PASS_WARN_AGE" 7
    update_login_defs_param "INACTIVE" 30

    # Fungsi bantu untuk atur UMASK di login.defs dan environment shell
    set_umask_if_missing() {
        local file="$1"

        if [ "$file" = "/etc/login.defs" ]; then
            if grep -q "^UMASK[[:space:]]\+027" "$file"; then
                echo -e "${green}[✓] UMASK 027 sudah ada di $file${nc}"
            elif grep -q "^UMASK[[:space:]]\+[0-9]\{3\}" "$file"; then
                sudo sed -i 's/^UMASK[[:space:]]\+[0-9]\{3\}/UMASK 027/' "$file"
                echo -e "${yellow}[~] Mengubah UMASK menjadi 027 di $file${nc}"
            else
                echo "UMASK 027" | sudo tee -a "$file" > /dev/null
                echo -e "${yellow}[+] Menambahkan UMASK 027 ke $file${nc}"
            fi
        else
            if grep -q "^umask[[:space:]]\+027" "$file"; then
                echo -e "${green}[✓] umask 027 sudah ada di $file${nc}"
            else
                echo "umask 027" | sudo tee -a "$file" > /dev/null
                echo -e "${yellow}[+] Menambahkan umask 027 ke $file${nc}"
            fi
        fi
    }

    # Set umask
    set_umask_if_missing "/etc/login.defs"

    # Cek dan set TMOUT di /etc/profile
    if grep -q "^TMOUT=" /etc/profile; then
        sudo sed -i 's/^TMOUT=.*/TMOUT=600/' /etc/profile
        echo -e "${yellow}[~] Mengupdate TMOUT=600 di /etc/profile${nc}"
    else
        echo "TMOUT=600" | sudo tee -a /etc/profile > /dev/null
        echo -e "${yellow}[+] Menambahkan TMOUT=600 ke /etc/profile${nc}"
    fi

    # Pastikan ada export TMOUT juga
    if ! grep -q "^export TMOUT" /etc/profile; then
        echo "export TMOUT" | sudo tee -a /etc/profile > /dev/null
        echo -e "${yellow}[+] Menambahkan export TMOUT ke /etc/profile${nc}"
    fi

    echo -e "${green}[✓] Pengaturan untuk user account dan environment berhasil diterapkan.${nc}"
}


set_timeout() {
    echo -e "${yellow}[*] Memeriksa dan menambahkan konfigurasi timeout untuk RHEL 5/6...${nc}"

    target_files=("/etc/bashrc" "/etc/profile")

    for file in "${target_files[@]}"; do
        if [ -f "$file" ]; then
            echo -e "${yellow}[~] Memeriksa $file...${nc}"

            if grep -q "^TMOUT=" "$file"; then
                echo -e "${yellow}[~] TMOUT sudah ada di $file, memperbarui ke TMOUT=600...${nc}"
                sudo sed -i 's/^TMOUT=.*/TMOUT=600/' "$file"
            else
                echo -e "${yellow}[~] Menambahkan TMOUT=600 ke $file...${nc}"
                echo "TMOUT=600" | sudo tee -a "$file" > /dev/null
            fi

            if ! grep -q "^export TMOUT" "$file"; then
                echo "export TMOUT" | sudo tee -a "$file" > /dev/null
            fi

            echo -e "${green}[✓] Timeout berhasil disetel di $file${nc}"
        else
            echo -e "${red}[X] File $file tidak ditemukan.${nc}"
        fi
    done

    echo -e "${green}[✓] Konfigurasi shell timeout selesai. Silakan relogin atau source file-nya.${nc}"
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
Compatible: Red Hat Enterprice 7.4 sampai 9

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


