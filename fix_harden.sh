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

# 1. OS Check
log "$blue" "==============================================="
log "$yellow" "Checking Operating System System Info..."

log "Operating System Info:"
echo "Distributor : $(lsb_release -i | cut -f2)"
echo "Description : $(lsb_release -d | cut -f2)"
echo "Release     : $(lsb_release -r | cut -f2)"
echo "Codename    : $(lsb_release -c | cut -f2)"
echo ""

# 2. System File Type
log "$blue" "==============================================="
log "$yellow" "Checking System File....."
log "File System (df -T):"
df -T | grep -v tmpfs
echo ""

# 3. Display all directory in /var:"
log "$blue" "==============================================="
log "$yellow" "Directory listing under /var:"
ls -l /var | grep "^d"
echo ""

# 4. Home Directory Display
log "$blue" "==============================================="
log "$yellow" "Directory Listing under /home:"
ls -l /home | grep "^d"
echo ""

}

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
if ! command -v ntpq &>/dev/null; then
    sudo apt-get install ntp -y > /dev/null 2>&1
fi

if [-f /etc/ntp.conf ]; then
   grep -q "server 172.18.104.166" /etc/ntp.conf || echo "server 172.18.104.166" | sudo tee -a /etc/ntp.conf > /dev/null
   sudo systemctl enable ntp > /dev/null 2>&1
   sudo systemctl restart ntp > /dev/null 2>&1
   ntpq -p
   echo -e "${green} NTP Aktif dan sudah terkonfigurasi.${nc}"

fi

#2. Konfigurasi Postfix hanya untuk lokal
echo -e "${yellow}[*] Mengecek dan mengonfigurasi Postfic...${nc}"
if ! dpkg -l | grep -qw postfix; then
    sudo apt-get install postfix -y > /dev/null 2>&1
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

apply_process_harden
sleep 2

disable_service
sleep 2
}

main
