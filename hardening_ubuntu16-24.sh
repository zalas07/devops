#!/bin/bash


green='\033[0;32m'
yellow='\033[1;33m'
red='\033[0;31m'
blue='\033[0;34m'
nc='\033[0m'

# === Logging Setup ===
LOG_DIR="/var/log/hardening"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/hardening_${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log_function() {
    local func_name="$1"
    echo -e "\n===== [$(date)] Menjalankan fungsi: $func_name =====" | tee -a "$LOG_FILE"
    
    { 
        "$func_name"
    } 2>&1 | tee -a "$LOG_FILE"
    
    echo -e "===== Selesai: $func_name =====\n" | tee -a "$LOG_FILE"
}



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

install_aide(){
    log "$blue" "============================================="
    log "$yellow" "Mengecek apakah paket AIDE sudah terinstall atau belum......"
    
    if ! dpkg -s aide >/dev/null 2>&1; then
        log "$red" "Paket AIDE belum terpasang"
        
        log "$yellow" "Memulai instalasi...."
        
        # Menggunakan apt-get dengan non-interaktif
        sudo DEBIAN_FRONTEND=noninteractive apt install aide -y
        
        if [ $? -eq 0 ]; then 
            log "$green" "AIDE Berhasil diInstall!"
            
            # Menunggu input dari user untuk konfigurasi AIDE
            log "$yellow" "Memulai konfigurasi AIDE..."
            
            # Meminta user untuk memasukkan lokasi instalasi dan domain/email
            echo -n "Masukkan lokasi instalasi AIDE (misalnya /usr/local/aide): "
            read install_location
            echo -n "Masukkan domain atau email: "
            read domain_or_email
            
            log "$yellow" "Proses konfigurasi untuk AIDE dengan lokasi $install_location dan domain/email $domain_or_email"
            
            # Edit konfigurasi AIDE setelah instalasi (file aide.conf)
            sudo sed -i "s|^database=file:/var/lib/aide/aide.db|database=file:$install_location/aide.db|" /etc/aide/aide.conf
            sudo sed -i "s|^report_url=|report_url=$domain_or_email|" /etc/aide/aide.conf
            
            # Inisialisasi AIDE setelah konfigurasi
            sudo aide --init
            
            log "$green" "Konfigurasi AIDE berhasil dilakukan!"
            
        else
            log "$red" "AIDE Gagal diInstall. Periksa koneksi dan repositori!"
            return 1
        fi
    else
        log "$green" "AIDE sudah terpasang"
        log "$blue" "Versi AIDE:"
        aide --version | head -n 1
    fi
}

setup_cron_aide(){

    log "$yellow" "Mengecek Cron Job AIDE di sudo Crontab......"

    # Pembuatan file aide.log jika belum ada
    if [ ! -d /var/log/aide ]; then
        sudo mkdir -p /var/log/aide
        sudo chown root:root /var/log/aide
        sudo chmod 750 /var/log/aide
    else
        log "$blue" "Directory Aide sudah Ada."
    fi

    # Membuat file log jika belum ada
    if [ ! -f /var/log/aide/aide.log ]; then
        sudo touch /var/log/aide/aide.log
        sudo chown root:root /var/log/aide/aide.log
        sudo chmod 640 /var/log/aide/aide.log
    else
        log "$blue" "File Log AIDE sudah ada."
    fi

    sleep 2

    cron_line="0 4 * * * /usr/bin/aide --check > /var/log/aide/aide.log 2>&1"
    if sudo crontab -l 2>/dev/null | grep -q "aide --check"; then
        log "$green" "Cron Job AIDE sudah ada!"
    else
        log "$blue" "Menambahkan Cron Job AIDE..."
        (sudo crontab -l 2>/dev/null; echo "$cron_line") | sudo crontab -
        log "$green" "Cron Job AIDE berhasil di tambahkan!"
    fi

    sleep 2
}

apply_process_harden(){

local sysctl_conf="/etc/sysctl.conf"
log "$blue" "================================================="
log "$yellow" "menambahkan parameter dumpable dan kernel randomize..."

#tambahkan atau update parameter fs.suid dumpable
if grep -q "^fs.suid_dumpable" "$sysctl_conf"; then

  sudo sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/' "$sysctl_conf"

else

  echo "fs.suid_dumpable = 0" | sudo tee -a "$sysctl_conf" > /dev/null

fi
sleep 2

#tambahkan atau update parameter kernel_randomisize_va_space
if grep -q "^kernel.randomize_va_space" "$sysctl_conf"; then

sudo sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' "$sysctl_conf"

else

echo  "kernel.randomize_va_space = 2" | sudo  tee -a  "$sysctl_conf" > /dev/null

fi
sleep 2

#penerapan konfigurasi

sudo sysctl -p  > /dev/null 2>&1

log "$green" "Parameter fs.suid_dumpable dan ASLR berhasil diterapkan"

#Set login banner

log "$blue" "================================================="
log "$yellow" "menambahkan banner message...."

#local motd="/etc/motd"
#local issue_file="/etc/issue"
#local issue_file_net = "/etc/issue.net"

local banner="The System is for the use of BRI Authorized Users Only.
Individuals using this computer system without authority, or in excess of their authority,
are subject to having all of their activities on this system monitored and recorded by system personnel. in the course of monitoring Individuals improperly using this system or in the course of system maintenance, the activities of authorized users may also be monitored."


if  [ -f /etc/motd ]; then
     #jikalu file motd ada
      echo "$banner" | tee /etc/motd /etc/issue /etc/issue.net > /dev/null

      #tambahkan banner ke dynamic MOTD
       if [[ -d /etc/update-motd.d ]]; then
            echo -e "#!/bin/bash\necho \"$banner\"" | sudo tee /etc/update-motd.d/99-custom-banner > /dev/null
             sudo chmod +x /etc/update-motd.d/99-custom-banner
       fi

        echo -e "${green}[+] motd, issue, issue.net, dan dynamic motd berhasil di konfigurasi.${nc}"
else
     #jikalau file motd tidak tersedia
      echo "$banner" | tee /etc/issue /etc/issue.net > /dev/null
       echo "${yellow}[!] file /etc/motd tidak ditemukan , hanya mengupdate issue dan issue.net.${nc}"
fi
sleep 2

}

install_apparmor() {
    echo "[*] Updating repository..."
    sudo apt update -y > /dev/null 2>&1

    echo "[*] Installing AppArmor and related packages..."
    sudo apt install -y apparmor apparmor-utils apparmor-profiles > /dev/null 2>&1

    echo "[*] Checking AppArmor version..."
    if ! apparmor_status > /dev/null 2>&1; then
        echo "[!] AppArmor status check failed. Exiting."
        exit 1
    fi

    #echo "[*] Updating parser.conf with write_cache and show_cache options..."
    #if [ -f /etc/apparmor/parser.conf ]; then
     #   grep -qxF 'write_cache' /etc/apparmor/parser.conf || echo 'write_cache' | sudo tee -a /etc/apparmor/parser.conf > /dev/null
     #   grep -qxF 'show_cache' /etc/apparmor/parser.conf || echo 'show_cache' | sudo tee -a /etc/apparmor/parser.conf > /dev/null
    #else
     #   echo "[!] parser.conf not found. Skipping."
    #fi

    echo "[*] Reloading all AppArmor profiles..."
    sudo apparmor_parser -r /etc/apparmor.d/* > /dev/null 2>&1

    echo "[*] Setting all profiles to enforce mode..."
    sudo aa-enforce /etc/apparmor.d/* > /dev/null 2>&1

    echo "[*] Enabling and restarting AppArmor service..."
    sudo systemctl enable apparmor > /dev/null 2>&1
    sudo systemctl restart apparmor > /dev/null 2>&1

    echo "[*] Verifying AppArmor service status..."
    sudo systemctl is-active --quiet apparmor && echo "[+] AppArmor service is active!" || echo "[!] AppArmor service is not active."

    echo "[+] AppArmor installation and configuration completed successfully!"
}

disable_service() {
log "$blue" "================================================="
log "$yellow" "[*] Menonaktifkan Service legacy yang tidak di butuhkan...${nc}"

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

    service_status=$(systemctl is-active "$service" 2>/dev/null)
    port_open=$(ss -tulpn | grep -i "$service")

    if [[ "$service_status" == "active" || -n "$port_open" ]]; then
        echo -e " Service $service AKTIF atau port terbuka, Mencoba nonaktifkan..."

        #stop  dan disable service jika di temukan
        sudo systemctl stop "$service" 2>/dev/null
        sudo systemctl disable "$service" 2>/dev/null

        #coba hapus xinetd jika ada 
        sudo rm -f "/etc/xinetd.d/$service"

        echo -e " Service $service berhasil di Nonaktifkan."
    else
        echo -e "Service $service tidak aktif dan port tidak terbuka."

    fi
    echo
done

echo -e "${green}[+} Selesai memproses semua service yang di targetkan.${nc}"
sleep 2

}


special_purpose_service(){
log "$blue" "===================================================="
log "$yellow" "[*] Menjalankan Special Purpose Services...${nc}"

#1. Konfigurasi & Aktivasi NTP
echo -e "${yellow}[*] Mengecek dan mengonfigurasi NTP...${nc}"

if command -v timedatectl &> /dev/null; then
   echo -e "${blue}[i] Menggunakan systemd-timesyncd (timedatectl)...${nc}"

   #Aktifkan service jika belum aktif
    sudo systemctl unmask systemd-timesyncd.service
    sudo systemctl enable systemd-timesyncd.service --now

   #tambahkan konfigurasi custom ke /etc/systemd/timesyncd.conf
   if grep -q "^#*NTP=" /etc/systemd/timesyncd.conf; then
      sudo sed -i 's|^#*NTP=.*|NTP=172.18.104.166|' /etc/systemd/timesyncd.conf
   else
      echo "NTP=172.18.104.166" | sudo tee -a /etc/systemd/timesyncd.conf > /dev/null
   fi

   sudo systemctl restart systemd-timesyncd.service
   echo -e "${green} NTP dikonfigurasi menggunakan systemd-timesyncd.${nc}"
   timedatectl status | grep "NTP synchronized"

else
   echo -e "${blue}[i] Menggunakan paket NTP biasa (ubuntu lawas)...${nc}"

   if ! dpkg -l | grep -qw ntp; then
       sudo apt-get install ntp -y
   fi

   if grep -q "^server" /etc/ntp.conf; then
       sudo sed -i '/^server /d' /etc/ntp.conf
   fi
   echo "Server 172.18.104.166" | sudo tee -a /etc/ntp.conf > /dev/null
   sudo systemctl restart ntp
   sleep 2

   echo -e "${yellow}[~]Mengecek Koneksi ke NTP Server...${nc}"
   if command -v ntpq &>/dev/null; then
        output=$(ntpq -p | grep "172.18.104.166")
        if [[ -n "$output" ]]; then
             echo -e "${green} NTP terkoneksi ke server 172.18.104.166:${nc}\n$output"
        else
             echo -e "${red} NTP tidak dapat terkoneksi ke server  172.18.104.166.${nc}"
        fi
    else
       echo -e "${red} Perintah NTP tidak tersedia ${nc}"
  fi

fi


#2. Konfigurasi Postfix hanya untuk lokal
echo -e "${yellow}[*] Mengecek dan mengonfigurasi Postfix...${nc}"
if ! dpkg -l | grep -qw postfix; then
    echo -e "${yellow}[~] Menginstall Postfix, Silahkan Pilih 'Local Only' saat diminta.${nc}"
    sudo DEBIAN_PRIORITY=high apt-get install postfix
    sudo apt-get install postfix
fi

if [ -f /etc/postfix/main.cf ]; then
   sudo sed -i 's/^inet_interface = .*/inet_interface = loopback_only/' /etc/postfix/main.cf
   sudo systemctl restart postfix > /dev/null 2>&1
   echo  -e "${green} Postfix di atur hanya di Localhost.${nc}"
fi

#3. Konfigurasi SNMPD
echo -e "${yellow}[*] Mengecek dan Mengonfigurasi SNMPD...${nc}"
if ! dpkg -l | grep -qw snmpd; then
    sudo apt-get install snmpd -y > /dev/null 2>&1
fi
sudo systemctl enable snmpd > /dev/null 2>&1
sudo systemctl restart snmpd > /dev/null 2>&1
echo -e "${green} SNMPD Diaktifkan.${nc}"

#4. Daftar service yang perlu di disable

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
echo -e "${yellow}[*] Menonaktifkan Service yang tidak di perlukan..${nc}"

for svc in "${disable_services[@]}"; do
    if dpkg -l | grep -qw "$svc"; then
       sudo systemctl stop "$svc" > /dev/null 2>&1
       sudo systemctl disable "$svc" > /dev/null 2>&1
       echo -e "${green} Service $svc di nonaktifkan.${nc}"
    fi
done


echo -e "${green} Module Purpose Special service selesai ${nc}"


}

network_parameters() {
    log "$blue" "=============================================="
    log "$yellow" "[*] Menetapkan Parameter keamanan jaringan di /etc/sysctl.conf...${nc}"

    # Daftar parameter yang ingin di set
    declare -A params=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
    )

    for param in "${!params[@]}"; do
        value="${params[$param]}"
        if grep -q "^$param" /etc/sysctl.conf; then
            current_value=$(grep "^$param" /etc/sysctl.conf | awk '{print $3}')
            if [[ "$current_value" == "$value" ]]; then
                echo -e "${green}[✓] $param sudah terset dengan nilai $value.${nc}"
            else
                sudo sed -i "s|^$param.*|$param = $value|" /etc/sysctl.conf
                echo -e "${yellow}[!] $param ditemukan, nilai diperbarui menjadi $value.${nc}"
            fi
        else
            echo "$param = $value" | sudo tee -a /etc/sysctl.conf > /dev/null
            echo -e "${cyan}[+] $param belum ada, ditambahkan dengan nilai $value.${nc}"
        fi
    done

    # Terapkan perubahan
    sudo sysctl -p > /dev/null
    echo -e "${green}[✓] Parameter Keamanan Jaringan berhasil diterapkan.${nc}"
}

network_parameters_host() {
    echo "[*] Starting network parameter hardening..."

    # Define parameters and their desired values
    declare -A sysctl_settings=(
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="0"
        ["net.ipv4.conf.default.secure_redirects"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
    )

    # Backup sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.bak

    for key in "${!sysctl_settings[@]}"; do
        value="${sysctl_settings[$key]}"

        # Check if key exists
        if grep -q "^$key" /etc/sysctl.conf; then
            # Update existing line
            sed -i "s|^$key.*|$key = $value|" /etc/sysctl.conf
            echo "[+] Updated $key to $value"
        else
            # Append new line
            echo "$key = $value" >> /etc/sysctl.conf
            echo "[+] Added $key = $value"
        fi
    done

    # Apply the changes
    sysctl -p

    echo "[*] Network parameters hardening completed."
}

audit() {
    echo -e "${yellow}[*] Memulai konfigurasi auditd dan rsyslog...${nc}"

    # --- Install paket yang diperlukan ---
    echo -e "${yellow}[~] Memeriksa dan menginstal auditd & rsyslog...${nc}"
    sudo apt-get update -qq
    sudo apt-get install -y auditd rsyslog

    echo -e "${green}[✓] Instalasi selesai.${nc}"

    # --- Pastikan direktori rules.d ada ---
    sudo mkdir -p /etc/audit/rules.d

    # --- Fungsi bantu untuk menulis file hanya jika isinya beda ---
    write_if_diff() {
        local filepath="$1"
        local content="$2"
        local tmpfile
        tmpfile=$(mktemp)

        echo "$content" > "$tmpfile"

        if [[ -f "$filepath" ]] && diff -q "$filepath" "$tmpfile" > /dev/null; then
            echo -e "${blue}[i] $filepath sudah sesuai, skip.${nc}"
        else
            echo -e "${yellow}[~] Menulis ulang $filepath...${nc}"
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
-w /var/run/faillock/ -p wa -k logins
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
    echo -e "${yellow}[~] Memeriksa konfigurasi /etc/audit/auditd.conf...${nc}"
    sudo sed -i 's/^max_log_file *=.*/max_log_file = 200/' /etc/audit/auditd.conf
    sudo sed -i 's/^max_log_file_action *=.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sudo sed -i 's/^space_left *=.*/space_left = 90/' /etc/audit/auditd.conf
    sudo sed -i 's/^space_left_action *=.*/space_left_action = ROTATE/' /etc/audit/auditd.conf
    sudo sed -i 's/^admin_space_left *=.*/admin_space_left = 80/' /etc/audit/auditd.conf
    sudo sed -i 's/^admin_space_left_action *=.*/admin_space_left_action = ROTATE/' /etc/audit/auditd.conf
    
    echo -e "${green}[✓] auditd.conf dikonfigurasi.${nc}"

    # === Reload Rules ===
    echo -e "${yellow}[~] Memuat ulang aturan audit menggunakan augenrules...${nc}"
    sudo augenrules --load

    # === Enable dan Restart Service ===
    echo -e "${yellow}[~] Mengaktifkan dan memulai layanan auditd dan rsyslog...${nc}"
    sudo systemctl enable --now auditd rsyslog

    echo -e "${green}[✓] Konfigurasi auditd dan rsyslog selesai.${nc}"
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
    if systemctl is-active --quiet sshd; then
        systemctl restart sshd
        echo "✅ SSH service restarted."
    elif systemctl is-active --quiet ssh; then
        systemctl restart ssh
        echo "✅ SSH service restarted."
    else
        echo "⚠️  SSH service not found or not active."
    fi
}

audit_wazuh_agent() {
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
    if sudo augenrules --load && sudo systemctl restart auditd; then
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
    echo -e "${yellow}[*] Memeriksa dan menambahkan konfigurasi timeout...${nc}"

    # Cek dan tambahkan konfigurasi timeout pada /etc/bash.bashrc
    echo -e "${yellow}[~] Memeriksa dan menambahkan konfigurasi timeout pada /etc/bash.bashrc...${nc}"
    if ! grep -q "TMOUT=600" /etc/bash.bashrc; then
        echo -e "${yellow}[~] Konfigurasi TMOUT belum ada, menambahkannya ke /etc/bash.bashrc...${nc}"
        sudo bash -c 'echo "TMOUT=600" >> /etc/bash.bashrc'
        sudo bash -c 'echo "export TMOUT" >> /etc/bash.bashrc'
    else
        echo -e "${green}[✓] Konfigurasi TMOUT sudah ada di /etc/bash.bashrc.${nc}"
    fi

    # Cek dan tambahkan konfigurasi timeout pada /etc/profile
    echo -e "${yellow}[~] Memeriksa dan menambahkan konfigurasi timeout pada /etc/profile...${nc}"
    if ! grep -q "TMOUT=600" /etc/profile; then
        echo -e "${yellow}[~] Konfigurasi TMOUT belum ada, menambahkannya ke /etc/profile...${nc}"
        sudo bash -c 'echo "TMOUT=600" >> /etc/profile'
        sudo bash -c 'echo "export TMOUT" >> /etc/profile'
    else
        echo -e "${green}[✓] Konfigurasi TMOUT sudah ada di /etc/profile.${nc}"
    fi

    echo -e "${green}[✓] Konfigurasi timeout selesai.${nc}"
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
    #set_umask_if_missing "/etc/bash.bashrc"
    #set_umask_if_missing "/etc/profile"

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
Compatible: Ubuntu 16.04 - 24.xx

EOF
echo -e "${nc}"
sleep 2

log_function baseline_check
sleep 2

log_function install_aide
sleep 2

log_function setup_cron_aide
sleep 2

log_function apply_process_harden
sleep 2

log_function install_apparmor
sleep 2

log_function disable_service
sleep 2

log_function special_purpose_service
sleep 2

log_function network_parameters
sleep 2

log_function network_parameters_host
sleep 2

log_function audit
sleep 2

log_function ssh_config
sleep 2

log_function audit_wazuh_agent
sleep 2

log_function set_timeout
sleep 2

log_function user_account_env
sleep 2

 # Pesan akhir
    echo -e "${green}[*] Server berhasil terhardening dan konfigurasi selesai.${nc}"
    echo -e "${green}[✓] Semua langkah telah berhasil diterapkan.${nc}"
    echo -e "${green}[✓] Server siap untuk operasional dengan konfigurasi yang aman.${nc}"


}

main
