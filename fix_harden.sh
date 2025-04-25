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
if ! dpkg  -s aide >/dev/null 2>&1; then

  log "$red" "Paket AIDE belum terpasang"

  log "$yellow" "Memulai instalasi...."
  sudo apt install aide -y >/dev/null 2>&1

  if [ $? -eq 0 ]; then 
      log "$green" "AIDE Berhasil diInstall!"
  else
      log "$red" "Aide Gagal diInstall periksa koneksi dan repositori!"
      return 1
  fi

else

log "$green" "AIDE sudah terpasang"
log "$blue" "Versi Aide:"
aide --version | head -n 1

fi

}
setup_cron_aide(){

log "$yellow" "Mengecek Cron Job AIDE di sudo Crontab......"

#pembuatan file aide.log
if [ ! -d  /var/log/aide ]; then
    sudo mkdir -p /var/log/aide
    sudo chown root:root /var/log/aide
    sudo chmod 750 /var/log/aide
else
    log "$blue" "Directory Aide sudah Ada."

fi
sleep 2

cron_line= " 0 4 * * *  /usr/bin/aide --check > /var/log/aide/aide.log 2>&1"
if sudo crontab -l 2>/dev/null | grep -q "aide --check"; then
   log "$green" "Cron Job AIDE sudah ada!"

else
   log "$blue" "Menambahkan Cron Job AIDE..."
   (sudo crontab -l 2>/dev/null; echo "$cron_line") | sudo crontab  -
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

#cek dan install apparmor
log "$blue" "=========================================================="
log "$yellow" "melakukan instalasi apparmor pada system...."
echo -e "${yellow}[*] Mengecek apakah Apparmor sudah terinstall...${nc}"
if ! command -v apparmor_status &> /dev/null; then
   echo -ne "{$yellow}[~] Apparmor belum terinstall. Menginstall Apparmor..."

  # sudo apt-get update -qq > /dev/null
   sudo apt-get install apparmor apparmor-utils -y > /dev/null 2>&1 &
   pid=$!

   spin='-\|/'
   i=0

#loop maksimal 120 detik (timeout), sambil ngecek apakah apparmor sudah ada dan tersedia
   for _ in {1..120}; do
      if command -v apparmor_status &> /dev/null; then
         echo -e "\r${green} Apparmor Berhasil diinstall.${nc} "

         break
      fi
      if ! kill -0 $pid 2>/dev/null; then
        echo -e "\r${red} Gagal menginstall Apparmor. cek koneksi dan repository.${nc}"
        break

      fi
      i=$(( (i+1) %4 ))
      printf "\r${yellow}[~] Menginstall Apparmor...${spin:$i:1}"
     sleep 0.5
   done

else
    echo -e "${green} Apparmor sudah terinstall.${nc}"
fi
sleep 2

# Aktifkan semua profile Enforce
echo -e "${yellow}[*] Menjalankan Enforce pada semua profile Apparmor...${nc}"
sudo aa-enforce /etc/apparmor.d > /dev/null 2>&1
echo -e "${green} Semua Profile Apparmor di set ke enforce mode.${nc}"
sleep 2

#tambahkan konfigurasi parser.conf
parser_conf="/etc/apparmor/parser.conf"
echo -e "${yellow}[*] Mengecek dan memperbaharui $parser_conf...${nc}"

if [ -f "$parser_conf" ]; then
    grep -qxF "write-cache" "$parser_conf" || echo  "write-cache" |  sudo tee -a  "$parser_conf" > /dev/null
    grep -qxF "show-cache" "$parser_conf" || echo "show-cache" | sudo tee -a "$parser_conf" > /dev/null
    echo -e "${green} File parser.conf berhasil di perbaharui.${nc}"
else
    echo -e "${red}[!] file $parser.conf tidak ditemukan. lewati update parser.conf.${nc}"
fi
sleep 2
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
log "$yellow" "[*] Menetapkan Parameter kemanan jaringan di directory /etc/sysctl.conf...${nc}"

#daftar parameter yang ingin di set

declare -A params=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.default.send_redirects"]="0"
)

for param in "${!params[@]}"; do
    value="${params[$param]}"
    if grep -q "^$param" /etc/sysctl.conf; then
       #ubah nilai jika sudah ada
       sudo sed -i "$|^$param.*|$param = $value|" /etc/sysctl.conf
    else
       #tambahkan jika belum ada
       echo "$param = $value" | sudo tee -a /etc/sysctl.conf > /dev/null
    fi
done

#terapkan perubahan

sudo sysctl -p > /dev/null

echo -e "${green} Parameter Keamanan Jaringan berhasil di terapkan .${nc}"

}

network_parameter_host_router(){
log "$blue" "========================================================="
log "$yellow" "[*] Mengatur parameter jaringan untuk Host dan Router...${nc}"

sysctl_conf="/etc/sysctl.conf"

param_list="
    net.ipv4.conf.all.accept_source_route=0
    net.ipv4.conf.default.accept_source_route=0
    net.ipv4.conf.all.accept_redirects=0
    net.ipv4.conf.default.accept_redirects=0
    net.ipv4.conf.all.secure_redirects=0
    net.ipv4.conf.default.secure_redirects=0
    net.ipv4.conf.all.log_martians=1
    net.ipv4.conf.default.log_martians=1
    net.ipv4.icmp_echo_ignore_broadcasts=1
    net.ipv4.icmp_ignore_bogus_error_responses=1
    net.ipv4.conf.all.rp_filter=1
    net.ipv4.conf.default.rp_filter=1
    net.ipv4.tcp_syncookies=1
"
    while IFS= read -r line; do
       key="${line%%=*}"
       value="${line#*=}"

     if grep -q "^$key" "$sysctl_conf"; then
         sudo sed -i "s|^$key.*|$key = $value|" "$sysctl_conf"
     else
         echo "$key = $value" | sudo tee -a "$sysctl_conf" > /dev/null
     fi
    done <<< "$param_list"


    echo -e "${blue}[~] Meng-apply parameter sysctl...${nc}"
    sudo sysctl -p > /dev/null 2>&1 && \
    echo -e "${green} Parameter jaringan berhasil di atur.${nc}" || \
    echo -e "${red} Gagal mengatur parameter jaringan.${nc}"


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

network_parameter_host_router
sleep 2
}

main
