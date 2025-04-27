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
Individuals using this Computer system without authority, or in excess of their authority,
are subject to having all of their activities on this system monitored and recorded."

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

    echo "[*] Updating parser.conf with write_cache and show_cache options..."
    if [ -f /etc/apparmor/parser.conf ]; then
        grep -qxF 'write_cache' /etc/apparmor/parser.conf || echo 'write_cache' | sudo tee -a /etc/apparmor/parser.conf > /dev/null
        grep -qxF 'show_cache' /etc/apparmor/parser.conf || echo 'show_cache' | sudo tee -a /etc/apparmor/parser.conf > /dev/null
    else
        echo "[!] parser.conf not found. Skipping."
    fi

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
    echo -e "${yellow}[*] Mengecek apakah auditd sudah terinstal...${nc}"

    # Cek apakah auditd sudah terinstal
    if ! command -v auditctl &> /dev/null; then
        echo -e "${yellow}[~] Menginstall auditd...${nc}"
        sudo apt install -y auditd &
    else
        echo -e "${green}[✓] Auditd sudah terinstal.${nc}"
    fi

    # Cek apakah rsyslog sudah terinstal
    echo -e "${yellow}[*] Mengecek apakah rsyslog sudah terinstal...${nc}"
    if ! command -v rsyslogd &> /dev/null; then
        echo -e "${yellow}[~] Menginstall rsyslog...${nc}"
        sudo apt install -y rsyslog &
    else
        echo -e "${green}[✓] Rsyslog sudah terinstal.${nc}"
    fi

    # Tunggu hingga kedua instalasi selesai
    wait

    # Cek dan setel konfigurasi auditd jika belum terkonfigurasi
    echo -e "${yellow}[*] Memeriksa dan mengonfigurasi auditd...${nc}"

    # Menambahkan konfigurasi untuk file /etc/audit/auditd.conf
    if ! grep -q "log_file" /etc/audit/auditd.conf; then
        echo -e "${yellow}[~] Mengonfigurasi auditd log storage...${nc}"
        echo "log_file = /var/log/audit/audit.log" | sudo tee -a /etc/audit/auditd.conf > /dev/null
    fi

    # Set agar log tidak otomatis dihapus
    if ! grep -q "max_log_file_action" /etc/audit/auditd.conf; then
        echo -e "${yellow}[~] Mengonfigurasi auditd untuk tidak menghapus log otomatis...${nc}"
        echo "max_log_file_action = keep_logs" | sudo tee -a /etc/audit/auditd.conf > /dev/null
    fi

    # Aktifkan auditd service
    echo -e "${yellow}[*] Mengaktifkan service auditd...${nc}"
    sudo systemctl enable auditd
    sudo systemctl start auditd

    # Cek dan setel aturan auditd untuk event
    echo -e "${yellow}[*] Memeriksa dan mengonfigurasi audit rules...${nc}"
    if ! grep -q "time-change" /etc/audit/audit.rules; then
        echo -e "${yellow}[~] Menambahkan rule untuk time-change...${nc}"
        echo "-w /etc/localtime -p wa -k time-change" | sudo tee -a /etc/audit/audit.rules > /dev/null
    fi

    if ! grep -q "login" /etc/audit/rules.d/50-logins.rules; then
        echo -e "${yellow}[~] Menambahkan rule untuk login events...${nc}"
        echo "-w /var/log/wtmp -p wa -k logins" | sudo tee -a /etc/audit/rules.d/50-logins.rules > /dev/null
    fi

    if ! grep -q "session" /etc/audit/rules.d/50-session.rules; then
        echo -e "${yellow}[~] Menambahkan rule untuk session events...${nc}"
        echo "-w /var/run/utmp -p wa -k session" | sudo tee -a /etc/audit/rules.d/50-session.rules > /dev/null
    fi

    if ! grep -q "delete" /etc/audit/rules.d/50-delete.rules; then
        echo -e "${yellow}[~] Menambahkan rule untuk delete events...${nc}"
        echo "-w /var/log/audit/ -p wa -k delete" | sudo tee -a /etc/audit/rules.d/50-delete.rules > /dev/null
    fi

    if ! grep -q "sudo" /etc/audit/rules.d/50-scope.rules; then
        echo -e "${yellow}[~] Menambahkan rule untuk sudo events...${nc}"
        echo "-w /etc/sudoers -p wa -k scope" | sudo tee -a /etc/audit/rules.d/50-scope.rules > /dev/null
    fi

    # Aktifkan rsyslog service
    echo -e "${yellow}[*] Mengaktifkan service rsyslog...${nc}"
    sudo systemctl enable rsyslog
    sudo systemctl start rsyslog

    # Cek apakah rsyslog mengirim log ke remote server
    if ! grep -q "remote" /etc/rsyslog.conf; then
        echo -e "${yellow}[~] Mengonfigurasi rsyslog untuk mengirim log ke remote server...${nc}"
        echo "*.* @@172.12.12.12:514" | sudo tee -a /etc/rsyslog.conf > /dev/null
    fi

    # Restart service untuk menerapkan perubahan
    sudo systemctl restart rsyslog

    echo -e "${green}[✓] Auditd dan Rsyslog berhasil dikonfigurasi.${nc}"
}

configure_ssh() {
    echo -e "${yellow}[*] Mengecek apakah SSH server sudah terinstal...${nc}"

    # Cek apakah SSH sudah terinstal
    if ! command -v sshd &> /dev/null; then
        echo -e "${yellow}[~] Menginstall OpenSSH Server...${nc}"
        sudo apt install -y openssh-server
    else
        echo -e "${green}[✓] OpenSSH Server sudah terinstal.${nc}"
    fi

    # Memastikan SSH berjalan
    echo -e "${yellow}[*] Memastikan service SSH berjalan...${nc}"
    sudo systemctl enable ssh
    sudo systemctl start ssh

    # Membuka file konfigurasi sshd_config
    echo -e "${yellow}[*] Membuka dan mengedit /etc/ssh/sshd_config untuk hardening SSH...${nc}"

    # Menonaktifkan login root
    sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

    # Menonaktifkan password authentication (gunakan key-based login)
    sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Mengubah port SSH (optional)
    # sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config  # jika ingin ganti port

    # Mengaktifkan log yang lebih ketat
    sudo sed -i 's/^#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

    # Menambahkan konfigurasi untuk mencegah brute-force attacks
    sudo sed -i 's/^#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
    sudo sed -i 's/^#MaxSessions 10/MaxSessions 5/' /etc/ssh/sshd_config

    # Konfigurasi tambahan sesuai dengan kebijakan:
    # Set Permissions pada /etc/ssh/sshd_config
    sudo chmod 600 /etc/ssh/sshd_config

    # Set SSH Protocol ke 2
    sudo sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config

    # Set LogLevel ke INFO
    sudo sed -i 's/^#LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config

    # Set X11Forwarding ke no
    sudo sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config

    # Set MaxAuthTries ke 4
    sudo sed -i 's/^#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config

    # Set ignoreRhosts ke yes
    sudo sed -i 's/^#IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config

    # Set HostBasedAuthentication ke no
    sudo sed -i 's/^#HostBasedAuthentication.*/HostBasedAuthentication no/' /etc/ssh/sshd_config

    # Set permitEmptyPasswords ke no
    sudo sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

    # Set permituserEnvirontment ke no
    sudo sed -i 's/^#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config

    # Set algoritma MAC yang disetujui hanya sha2-512 dan sha2-256
    sudo sed -i '/^#MACs/c\MACs hmac-sha2-512,hmac-sha2-256' /etc/ssh/sshd_config

    # Set idle timeout interval ke 300 detik
    sudo sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sudo sed -i 's/^#ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

    # Set login grace time ke 60 detik
    sudo sed -i 's/^#LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config

    # Restart SSH untuk menerapkan perubahan
    sudo systemctl restart ssh

    echo -e "${green}[✓] SSH Server berhasil dikonfigurasi sesuai dengan kebijakan keamanan.${nc}"
}

# Fungsi untuk konfigurasi user account dan environment
user_account_env() {
    echo -e "${yellow}[*] Menyiapkan pengaturan untuk user account dan environment...${nc}"

    # Mengatur expiration password
    echo "PASS_MAX_DAYS 90" >> /etc/login.defs
    echo "PASS_MIN_DAYS 7" >> /etc/login.defs
    echo "PASS_WARN_AGE 7" >> /etc/login.defs
    echo "INACTIVE 30" >> /etc/login.defs

    # Mengatur umask default di /etc/bashrc dan /etc/profile
    if ! grep -q "umask 027" /etc/bashrc; then
        echo "umask 027" >> /etc/bashrc
    fi
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
    fi

    # Mengatur shell timeout menjadi 600 detik
    echo "TMOUT=600" >> /etc/profile

    # Mengecek konfigurasi yang telah diterapkan
    echo -e "${green}[✓] Pengaturan untuk user account dan environment berhasil diterapkan.${nc}"
}

add_wazuh_audit_rules() {
    echo -e "${yellow}[*] Menambahkan aturan audit untuk Wazuh...${nc}"

    # Lokasi file audit rules
    RULES_FILE="/etc/audit/rules.d/audit.rules"

    # Daftar aturan yang ingin ditambahkan
    RULES=(
        "-a always,exit -F arch=b64 -S execve -F auid>=0 -F egid!=994 -F auid=-1 -F key=audit-wazuh-c"
        "-a always,exit -F arch=b32 -S execve -F auid>=0 -F egid!=994 -F auid=-1 -F key=audit-wazuh-c"
    )

    # Mengecek apakah file audit rules ada
    if [[ ! -f "$RULES_FILE" ]]; then
        echo -e "${red}[X] File $RULES_FILE tidak ditemukan!${nc}"
        return 1
    fi

    # Menambahkan aturan-aturan yang diperlukan
    for rule in "${RULES[@]}"; do
        if ! grep -q "$rule" "$RULES_FILE"; then
            echo "$rule" | sudo tee -a "$RULES_FILE" > /dev/null
            echo -e "${green}[✓] Aturan '$rule' berhasil ditambahkan ke $RULES_FILE${nc}"
        else
            echo -e "${yellow}[~] Aturan '$rule' sudah ada di $RULES_FILE${nc}"
        fi
    done

    # Memuat ulang aturan audit
    sudo augenrules --load
    if [[ $? -eq 0 ]]; then
        echo -e "${green}[✓] Aturan audit berhasil diterapkan dan di-reload.${nc}"
    else
        echo -e "${red}[X] Gagal memuat ulang aturan audit.${nc}"
    fi
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

install_aide
sleep 2

setup_cron_aide
sleep 2

#apply_process_harden
#sleep 2

disable_service
sleep 2

special_purpose_service
sleep 2

network_parameters
sleep 2

network_parameters_host_router
sleep 2

audit
sleep 2
configure_ssh
sleep 2
user_account_env
sleep 2
}

main
