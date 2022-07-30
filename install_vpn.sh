#!/bin/bash
###### function list here #####
if test -z "$BASH_VERSION"; then
  echo "Please run this script using bash, not sh or any other shell." >&2
  exit 1
fi

_() {

#set -euo pipefail

# Declare an array so that we can capture the original arguments.
declare -a ORIGINAL_ARGS
# Define I/O helper functions.
error() {
  if [ $# != 0 ]; then
    echo -en '\e[0;31m' >&2
    echo "$@" | (fold -s || cat) >&2
    echo -en '\e[0m' >&2
  fi
}

fail() {
  local error_code="$1"
  shift
  if [ "${SHOW_FAILURE_MSG:-yes}" = "yes" ] ; then
    echo "*** INSTALLATION FAILED ***" >&2
    echo ""
  fi
  error "$@"
  echo "" >&2
  # Users can export REPORT=no to avoid the error-reporting behavior, if they need to.
  echo "You can report bugs at: http://github.com/peyoot/pvpn" >&2
  exit 1
}


set_umask() {
  # Use umask 0022, to minimize how much 'mkdir -m' we have to do, etc. See #2300.
  umask 0022
}

assert_on_terminal() {
  if [ "no" = "$USE_DEFAULTS" ] && [ ! -t 1 ]; then
    REPORT=no fail "E_NO_TTY" "This script is interactive. Please run it on a terminal."
  fi

  # Hack: If the script is being read in from a pipe, then FD 0 is not the terminal input. But we
  #   need input from the user! We just verified that FD 1 is a terminal, therefore we expect that
  #   we can actually read from it instead. However, "read -u 1" in a script results in
  #   "Bad file descriptor", even though it clearly isn't bad (weirdly, in an interactive shell,
  #   "read -u 1" works fine). So, we clone FD 1 to FD 3 and then use that -- bash seems OK with
  #   this.
  exec 3<&1
}

usage() {
  echo "usage: $SCRIPT_NAME" >&2
  echo "This is an interactive installation script" >&2
  echo "You'll need to choose VPN type and VPN mode in the process" >&2
  echo '' >&2
  echo 'You can choose openVPN only, ie openvpn server and openvpn client with easyrsa PKI' >&2
  echo 'If you choose strongswan, it will install both strongswan and openVPN, and openvpn will use strongswan-pki as well' >&2
  echo 'VPN server need to be installed in an environment with public IP address.' >&2
  echo 'you can choose to build new CA or used existing CA by providing download url' >&2 
  echo '' >&2
  exit 1
  exit 1
}


handle_args() {
  SCRIPT_NAME=$1
  shift

  while getopts ":d:" opt; do
    case $opt in
      d)
        USE_DEFAULTS="yes"
        ;;
      *)
        usage
        ;;
    esac
  done


  # Keep a copy of the ORIGINAL_ARGS so that, when re-execing ourself,
  # we can pass them in.
  ORIGINAL_ARGS=("$@")

  # Pass positional parameters through
  shift "$((OPTIND - 1))"

  if [ $# = 1 ] && [[ ! $1 =~ ^- ]]; then
    BUNDLE_FILE="$1"
  elif [ $# != 0 ]; then
    usage
  fi
}

prompt() {

  local VALUE

  # We use "bold", rather than any particular color, to maximize readability. See #2037.
  echo -en '\e[1m' >&3
  echo -n "$1 [$2]" >&3
  echo -en '\e[0m ' >&3
  read -u 3 VALUE
  if [ -z "$VALUE" ]; then
    VALUE=$2
  fi
  echo "$VALUE"
}

prompt-numeric() {
  local NUMERIC_REGEX="^[0-9]+$"
  while true; do
    local VALUE=$(prompt "$@")

    if ! [[ "$VALUE" =~ $NUMERIC_REGEX ]] ; then
      echo "You entered '$VALUE'. Please enter a number." >&3
    else
      echo "$VALUE"
      return
    fi
  done
}

prompt-yesno() {
  while true; do
    local VALUE=$(prompt "$@")

    case $VALUE in
      y | Y | yes | YES | Yes )
        return 0
        ;;
      n | N | no | NO | No )
        return 1
        ;;
    esac

    echo "*** Please answer \"yes\" or \"no\"."
  done
}

check_root() {
  ROOTUID="0"

  if [ "$(id -u)" -ne "$ROOTUID" ] ; then
    echo "This script must be executed with root privileges. try with sudo or root account"
    exit 1
  fi
}

prepare_installation_paras() {

#record install log
if [ -z /var/log/pvpn_install.log ]; then
  echo "Install script first time run at:" |tee /var/log/pvpn_install.log
  date |tee -a /var/log/pvpn_install.log
else
  echo "Install script run again at:" |tee -a /var/log/pvpn_install.log
  date |tee -a /var/log/pvpn_install.log
fi


#check out ubuntu version
UBUNTU_VERSION="$(lsb_release --release | cut -f2)"
ARR_E+=("14.04")
ARR_E+=("16.04")
ARR_N+=("18.04")
ARR_N+=("20.04")
ARR_N+=("22.04")

if [[ "${ARR_E[@]}" =~ "$UBUNTU_VERSION" ]]; then
    OVPN_CONFIG_SDIR="/etc/openvpn"
    OVPN_SSERVICE="openvpn@server"
    OVPN_CONFIG_CDIR="/etc/openvpn"
    OVPN_CSERVICE="openvpn@client"
    OVPN_COMPRESS="comp-lzo"
    OVPN_LOG_DIR="/var/log"
    DNS_UPDATER="update-resolv-conf"
elif [[ "${ARR_N[@]}" =~ "$UBUNTU_VERSION" ]]; then
    OVPN_CONFIG_SDIR="/etc/openvpn/server"
    OVPN_SSERVICE="openvpn-server@server"
    OVPN_CONFIG_CDIR="/etc/openvpn/client"
    OVPN_CSERVICE="openvpn-client@client"
    OVPN_COMPRESS="compress lz4-v2"
    OVPN_LOG_DIR="/var/log/openvpn"
    DNS_UPDATER="update-systemd-resolved"
else 
    if prompt-yesno "This script only verified in ubuntu. Please do not try it in non-debian distribution!Contine?" no; then 
        echo "only ubuntu are verified. Take your own risk to try it in other version! Type yes to continue"
        OVPN_CONFIG_SDIR="/etc/openvpn/server"
        OVPN_SSERVICE="openvpn-server@server"
        OVPN_CONFIG_CDIR="/etc/openvpn/client"
        OVPN_CSERVICE="openvpn-client@client"
        OVPN_COMPRESS="compress lz4-v2"
        OVPN_LOG_DIR="/var/log/openvpn"
        DNS_UPDATER="update-systemd-resolved"
    else
        echo "pvpn installation aborted"
        exit 1
    fi
fi
echo "Your ubuntu version is: ${UBUNTU_VERSION}"
#set necessary variables
NEEDPKICA="yes"
NEEDDH="yes"
ADD_CLIENT="yes"
CLIENT_USER="client"
NEED_SCERT="yes"
MANUALLY_DOWNLOAD="no"
KEEP_IPSEC_CONFIG="no"
KEEPSTUNNEL="no"
KEEPOVPN_SCONFIG="no"
#USE_DEFAULTS is a parameter for palfort vpn only. If you try to install your own VPN system, just dont use it.
if [ "yes" = "$USE_DEFAULTS" ] ; then
   VPN_TYPE="dual"
   if prompt-yesno "Install palfort VPN client OK?" yes; then
        VPN_MODE="client"
      else
        VPN_MODE="server"
   fi
else 
  echo -n 'PVPN installation scripts  makes it easy to set up openvpn and strongswan in your own server and PC within NAT '
  if [ -z "${CHOSEN_VPN_MODE:-}" ]; then
    echo "You can:"
    echo ""
    echo "1. Install VPN server with public IP in the internet (press enter to accept this default)"
    echo "2. Install VPN client on a PC in your home or office, so that it can set up VPN tunnel with the VPN server "
    echo "3. Extend webfs service time on existing VPN Server so that client can download certifications from this server."
    echo ""
    CHOSEN_VPN_MODE=$(prompt-numeric "How are you going to install?" "1")
  fi
  if [ "1" = "$CHOSEN_VPN_MODE" ] ; then
    echo "Select VPN server mode" | tee -a /var/log/pvpn_install.log
    VPN_MODE="server"
  elif [ "2" = "$CHOSEN_VPN_MODE" ]; then
    echo "Select VPN client mode " | tee -a /var/log/pvpn_install.log
    VPN_MODE="client"
  else
    if [ -e /etc/webfsd.conf ]; then
      echo "Please input the expire time for webfs service "
      OPEN_HOURS=$(prompt "Enable webfs for another 12 hours:" "12")
      systemctl start webfs
      echo "webfs servcie will be stop after specified time for security issue. You won't be able to download related client certs at that time"
      echo "systemctl stop webfs" |at now + ${OPEN_HOURS} hours
      echo "you can re-enable webfs service at any time when you need it"
      exit 1
    else
      echo "you haven't installed webfs on the server"
      exit 1
    fi
  fi
    
  if [ -z "${CHOSEN_VPN_TYPE:-}" ]; then
    echo "You can:"
    echo ""
    echo "1. Install openvpn+stunnel only and use easyrsa3 as PKI( enter to accept this default)"
    echo "2. Install Strongswan only and use ipsec PKI tool"
    echo "3. Install both strongswan and openvpn, use ipsec PKI tool "
    echo ""
    CHOSEN_VPN_TYPE=$(prompt-numeric "Please choose which vpn type you're about to install?" "1")
  fi
  if [ "1" = "$CHOSEN_VPN_TYPE" ]; then
    echo "Select openvpn over stunnel" | tee -a /var/log/pvpn_install.log
    VPN_TYPE="openvpn"
    if prompt-yesno "Woud you like to use tap interface in openvpn?" yes; then
       OVPN_INTERFACE="tap"
    else
       OVPN_INTERFACE="tun"
    fi

  elif [ "2" = "$CHOSEN_VPN_TYPE" ]; then
    echo "Select strongswan sole" | tee -a /var/log/pvpn_install.log
    VPN_TYPE="strongswan"
  else
    echo "Select both openvpn/stunnel and strongswan VPN" | tee -a /var/log/pvpn_install.log
    VPN_TYPE="dualvpn"
    if prompt-yesno "Woud you like to use tap interface in openvpn?" yes; then
       OVPN_INTERFACE="tap"
    else
       OVPN_INTERFACE="tun"
    fi
  fi
fi
}

confirm_install() {
  echo "sctips are about to install software you choose"
  echo "you've chosen $VPN_TYPE"
  echo "prepare some software packages for scripts to use"
  echo "apt update" | tee -a /var/log/pvpn_install.log 
  apt update
  apt -y install gawk
  if [ ! -e /usr/bin/zip ]; then
     echo "apt install -y zip" | tee -a /var/log/pvpn_install.log
     apt install -y zip
  fi

  SERVER_URL=$(prompt "Please input the server public IP:" "")
  if [ -z "$SERVER_URL" ]; then
     echo "you need input the VPN server's public IP address so that scripts know how to configure it"
     echo "scripts now auto-detect your IP address. It may not be the right one if you use some cloud servers which didin't bind public IP to interface"
     echo "SERVER CIDR detecting $(ip -o addr|grep dnamic |awk '/^[0-9]/ {print gensub(/(.*)/,"\\1","g",$4)}' |cut -d'/' -f 1)"
     IPADDR=$(ip -o addr | grep global | awk '/^[0-9]/ {print gensub(/(.*)\/(.*)/,"\\1","g",$4)}'|head -1)
     if prompt-yesno "Is your server IP address ${IPADDR} ?" yes; then
       SERVER_URL="$IPADDR"
     else
       echo "pvpn installation aborted"
       exit 1
     fi
  fi

#  apt install -y net-tools
  if [ "server" = "$VPN_MODE" ]; then
#check webf availability
    if [ ! -e /etc/webfsd.conf ]; then
      if prompt-yesno "Would you like to install webfs so that scripts can help you to generate client certs download URL?" "yes" ; then
          echo "webfs will be installed.please wait...."
          echo "apt install -y webfs"
          apt install -y webfs at
          echo "sleep 1"
          sleep 1
          sed -i "/web_extras=\"\"/cweb_extras=\"-b pvpn:download\"" /etc/webfsd.conf
          echo "mkdir -p /var/www/html/pvpn" | tee -a /var/log/pvpn_install.log
          mkdir -p /var/www/html/pvpn
          echo "create /var/www/html/pvpn for webfs"
      else
          echo "you've bypass the webfs installation. You'll need to manually copy client certs to client side later"
      fi
    fi
  fi
  
  if [ "openvpn" = "$VPN_TYPE" ]; then
    openvpn_install
#  elif [ "strongswan" =  "$VPN_TYPE" ]; then
#    strongswan_install
  else
    ipsec_install
  fi
}


confirm_setting() {
  echo "sctips are about to setup software based on your choise"
  echo "you've chosen $VPN_TYPE"
  if [ "openvpn" = "$VPN_TYPE" ]; then
    openvpn_config
#  elif [ "strongswan" = "$VPN_TYPE" ]; then
#    strongswan_config
  else
    ipsec_config
  fi
}

finish_pvpn() {
  IPSECINSTALLED=$(cat /var/log/pvpn_install.log |grep ipsecinstalled)
  OVPNINSTALLED=$(cat /var/log/pvpn_install.log |grep ovpninstalled)
  PVPNINSTALLED=$(cat /var/log/pvpn_install.log |grep pvpninstalled)

  if [ "server" = "$VPN_MODE" ]; then 
    if [ -e /etc/webfsd.conf ]; then
      echo "start webfs service"
      systemctl start webfs
      echo "webfs servcie will be stop after 24 hours for security issue. You won't be able to download related client certs at that time"
      echo "systemctl stop webfs" |at now + 24 hours
      echo "you can re-enable webfs service any time by command: sudo systemctl start webfs if you need more time to download client certs"
      echo "You need input username and password if you want to download your certs manually,default username and password is pvpn/download"
    fi
    NETINTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ "openvpn" != "$VPN_TYPE" ]; then
#do ipsec finishing stuff here
:<<!
#comment out the following because rightdns do the same
      if ! grep "dns" /etc/strongswan.conf >/dev/null
      then
        PUSH_DNS=yes
      fi
      if [ "yes" = "$PUSH_DNS" ]; then
        echo "add dns in strongswan"
        sed -i '/load_modular/a\\tdns=1.1.1.1' /etc/strongswan.conf
      else
        echo "strongswan already have dns in config file"
      fi
!

#additional ipsec first time run work
      if [ -z "$IPSECINSTALLED" ]; then
        echo "ipsecinstalled is ${IPSECINSTALLED}"
# set iptables for ipsec
        IPSEC_RULES=$(iptables -nL -t nat|grep  10.100.100.0 -m -1 | awk '{print $4}')
        if [ -n "$IPSEC_RULES" ]; then
            echo "ipsec iptables rule exist"
          if prompt-yesno "would you like to remove iptables" "no" ; then
             echo "removing ipsec iptables rules"
             iptables -t nat -D POSTROUTING -o ${NETINTERFACE} -s 10.100.100.0/24 -j MASQUERADE
             iptables-save > /etc/iptables.rules
          else
             echo "keep ipsec itable rules"
          fi
        else
          echo "choose to set iptables rule for ipsec"
          if prompt-yesno "would you like to set ipsec iptables rules so that client may use tunnel to access internet" "yes" ; then
             echo "set ipsec iptables rules" |tee -a /var/log/pvpn_install.log
             iptables -t nat -A POSTROUTING -o ${NETINTERFACE} -s 10.100.100.0/24 -j MASQUERADE
             iptables-save > /etc/iptables.rules
          else
             echo "keep ipsec iptables rules untapped"
          fi
        fi

        if [ "yes" = "$VIRTUALIP" ]; then
          if prompt-yesno "would you like to set server additional IP from virtual IP pool?" "no" ; then

            SERVER_VIRTUALIP=$(ip addr |grep 10.100.100.254 | awk '{print $2}'|cut -d'/' -f 1)
            if [ -n "$SERVER_VIRTUALIP" ]; then
              echo "VPN server have already set an IP ${SERVER_VIRTUALIP}"
            else
              echo "set VPN server ip as 10.100.100.254" |tee -a /var/log/pvpn_install.log
              ip addr add 10.100.100.254/24 dev ${NETINTERFACE}
            fi
          else
            echo "Server will not have an additonal IP address from virtual IP pool"
          fi
        fi
#disable cloud server keep alive
        if prompt-yesno "Do you use cloud server which ethernet interface didn't bind the public IP by default? You may want to disable keep alive in server" "yes" ; then
          if [ "$(grep -c keep_alive /etc/strongswan.conf)" = "0" ]; then
             echo "set keep_alive=0 in strongswan.conf for this cloud vps" |tee -a /var/log/pvpn_install.log
             sed -i "/plugins/i\ \t\keep_alive = 0" /etc/strongswan.conf 
          else
             echo "keep_alive already set"
          fi
        fi
      
#end of disable cloud server  keep alive
        echo "ipsecinstalled" >> /var/log/pvpn_install.log
      fi
#end of first tim run  work

      echo "restart  ipsec "
      ipsec restart
    fi
    if [ "strongswan" != "$VPN_TYPE" ]; then
#ovpn first time run work start
#do ovpn finishing stuff here
      if [ -z "$OVPNINSTALLED" ]; then
        TAP_RULES=$(iptables -nvL|grep tap0 -m 1 | awk '{print $6}')
#      echo "TAP_RULES is ${TAP_RULES}"
#      VIRTUALIP_RULES=$(iptables -nL|grep 10.10.100.0 -m 1 | awk '{print $5}')
        if [ -n "$TAP_RULES" ]; then
          echo "tap0 iptables rule exist"
        else
          echo "set iptables rule for openvpn" |tee -a /var/log/pvpn_install.log
          iptables -A FORWARD -i ${OVPN_INTERFACE}0 -o ${NETINTERFACE} -s 10.100.101.0/24 -m conntrack --ctstate NEW -j ACCEPT
          iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
          iptables -t nat -A POSTROUTING -o ${NETINTERFACE} -s 10.100.101.0/24 -j MASQUERADE
          iptables-save > /etc/iptables.rules
        fi
        echo "openvpninstalled" >> /var/log/pvpn_install.log
      fi
    fi
#end ofovpn first time run work
    if [ -z "$PVPNINSTALLED" ]; then

#both type need to setup iptables restore in rc.local
      echo "Now setup iptables restore in rc.local and finishing VPN server setup"
      echo 1 > /proc/sys/net/ipv4/ip_forward
      CHECKFORWARD=$(cat /etc/sysctl.conf |grep "net.ipv4.ip_forward=")
      if [ -z "$CHECKFORWARD" ]; then
         echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
      else
         CHECKFORWARD=$(cat /etc/sysctl.conf |grep "#net.ipv4.ip_forward=")
         if [ -z "$CHECKFORWARD" ]; then
            CHECKFORWARD=$(cat /etc/sysctl.conf |grep "net.ipv4.ip_forward=0")
            if [ -n "$CHECKFORWARD" ]; then
              sed -i "s/^net.ipv4.ip_forward=0/net.ipv4.ip_forward=1/" /etc/sysctl.conf
            fi
         else
            sed -i "s/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/" /etc/sysctl.conf
         fi
      fi

####add iptables restore to rc.local service####
      if [ -n /etc/systemd/system/rc-local.service ]; then
        ln -fs /lib/systemd/system/rc-local.service /etc/systemd/system/rc-local.service
      fi
      cat /etc/systemd/system/rc-local.service |grep Install
      if [ $? -eq 0 ]; then
        echo "you've setup rc.local service already, please manually check if you've configure iptables-restore there"
      else
        echo "Install rc.local service for pvpn iptables restore"
        echo "" >> /etc/systemd/system/rc-local.service
        echo "[Install]" >> /etc/systemd/system/rc-local.service
        echo "WantedBy=multi-user.target" >> /etc/systemd/system/rc-local.service
        echo "Alias=rc-local.service" >> /etc/systemd/system/rc-local.service
        touch  /etc/rc.local
        echo "#!/bin/bash" >> /etc/rc.local
        echo "iptables-restore < /etc/iptables.rules" >> /etc/rc.local
        chmod a+x /etc/rc.local 
        echo "service to restore iptables rules after reboot is set"
      fi
      echo "pvpn have installed an configured as what you specified"
      echo "pvpninstalled" >> /var/log/pvpn_install.log
    fi
  else
    echo "You have set up your vpn client mode with pvpn tools.Please note auto-configure only support default vpn client user. If you have multiple user please manually configure it later "
    if prompt-yesno "would you like to download client certs and config file from server" "yes" ; then
      if [ "openvpn" != "$VPN_TYPE" ]; then
        echo "Scripts now try to download ipsec client certs and config from server"
        wget http://${SERVER_URL}:8000/pvpn/pvpn-ipsec-${CLIENT_USER}certs.zip --user pvpn --password download
        if prompt-yesno "Would you like to use client config file generate from server in this download.If your server doesn't bind public IP and you don't know how to config ipsec client. You can try with it" "no" ; then
          unzip -o pvpn-ipsec-${CLIENT_USER}certs.zip -d /etc/
        else
          unzip -o pvpn-ipsec-${CLIENT_USER}certs.zip -d /etc/ -x ipsec.conf ipsec.secrets
        fi
      fi
      if [ "strongswan" != "$VPN_TYPE" ]; then
        echo "Scripts now will try to download openvpn client configure from server and extract it into the right place"
#
        wget http://${SERVER_URL}:8000/pvpn/pvpn-openvpn-${CLIENT_USER}certs.zip --user pvpn --password download
        unzip -o pvpn-openvpn-${CLIENT_USER}certs.zip -x ${CLIENT_USER}.ovpn -d /etc/openvpn/
      fi
      sleep 1
      echo "your vpn client have been installed and is ready for your usage."
      rm -rf pvpn*.zip
    else
      echo "To start the VPN service please download the client certs and put it in the right place"
      echo "If you download pvpn-openvpn-clientcerts.zip from http://$SERVER_URL:8000/pvpn, just run: sudo unzip -j pvpn-openvpn-clientcerts.zip -d /etc/openvpn/"
    fi
      echo "In ubuntu 18.04/20.04  you can use systemctl enable/disable openvpn-client@client to add it into system service and auto run after next boot"
      echo "or you can manually start openvpn by input: openvpn /etc/openvpn/client.conf (Ubuntu 16.04) or openvpn /etc/openvpn/client/client.conf (Ubuntu 18.04)"
  fi
}

use_existingCA() {
  if [ "openvpn" = "$VPN_TYPE" ]; then
    CA_FILE="/etc/openvpn/ca.crt"
  else 
    CA_FILE="/etc/ipsec.d/cacerts/cacert.pem"
  fi
  if [ -e $CA_FILE ]; then
    echo "Scripts will use CA file $CA_FILE"
  else 
    echo "CA doesn't exist"
    if prompt-yesno "Palfort administrator can download it automatically. Would you like to download it? if you're not authorized, please type no" "no" ; then
       download_CA
    else
        echo "please put your CA to $CA_FILE first and then try again. The installation now aborded"
        exit 1
    fi
  fi 
}

download_CA() {
  echo "downloading CA won't be available to public user right now."
  exit 1
}

InitPKI_buildCA() {
  echo "Scripts will help you to initial PKI and generate your own CA now" 
  if [ "openvpn" = "$VPN_TYPE" ] ; then
    ./easyrsa init-pki
    sleep 3
    echo "Easyrsa PKI initialed" 
    if [ ! -e /etc/openvpn/easyrsa/vars ] ; then
      mv vars.example vars
    fi
    if prompt-yesno "Default key size is 2048 bit. Change to 1024 bit for quicker access with legacy ubuntu before 18.04?" "no" ; then
      echo "set_var EASYRSA_KEY_SIZE 1024" >> /etc/openvpn/easyrsa/vars
    fi
    echo "about to build CA"
    ./easyrsa build-ca nopass
    sleep 1
    echo "CA has been generated by EASYRSA!"
  else
    echo "Initial ipsec pki and build CA now"
    CA_CN=$(prompt "Please input the common name of CA" "PVPN CA ${SERVER_URL}")
    ipsec pki --gen --outform pem > /etc/ipsec.d/private/cakey.pem
    ipsec pki --self --in /etc/ipsec.d/private/cakey.pem --dn "C=CN,O=Palfort,CN=${CA_CN}" --ca --outform pem > /etc/ipsec.d/cacerts/cacert.pem
    echo "CA key and CA cert generated"

  fi
}


generate_certs() {
  echo "now we have CA in place, start to generate certs now!" 
  if [ "openvpn" = "$VPN_TYPE" ] ; then
#use easyrsa to generate certs
#check if server cert is available or not 
    if [ -e /etc/openvpn/server.crt ]; then
      if prompt-yesno "Server cert already exist, generate a new one?" "no" ; then
        NEED_SCERT="yes"
      else
        NEED_SCERT="no"
      fi
    fi
    if [ "yes" = "$NEED_SCERT" ]; then
        ./easyrsa build-server-full server nopass
        echo "copy server key and cert to config folder"
        openssl pkcs12 -export -clcerts -in ./pki/issued/server.crt -inkey ./pki/private/server.key -out /etc/stunnel/server.p12 -passout pass:
        cp  ./pki/ca.crt ./pki/private/server.key ./pki/issued/server.crt /etc/openvpn/
        if [ -e /etc/openvpn/dh.pem ] ; then
            if prompt-yesno "you've got dh.pem in PKI, use it?" "yes" ; then
               echo "use current dh.pem"
               NEEDDH="no"
            fi
        fi
        if [ "yes" = "$NEEDDH" ] ; then
          ./easyrsa gen-dh
          echo "copy dh to config folder"
          cp ./pki/dh.pem /etc/openvpn/
        fi
        sleep 3
    fi
    echo "Scripts will help you generate client certs"
    echo "By default client.key and client.crt will be generated!."
    if [ -e ./pki/issued/client.crt ]; then
      if prompt-yesno "client cert already exist, generate a new one?" "no" ; then
          CLIENT_USER=$(prompt "Please input the username of client, use client- as prefix. It will keep original one and generate a new user cert:" "client")
      else
          ADD_CLIENT="no"
      fi
    fi
    if [ "yes" = "$ADD_CLIENT" ]; then
        ./easyrsa build-client-full ${CLIENT_USER} nopass
    fi


    if prompt-yesno "you've generated a client cert. Do you want to pack all client certs stuff for easy downloading" "yes" ; then
      echo "copy ca and client key,cert to /tmp/openvpn and zip it there"
      mkdir -p /tmp/openvpn
      cp  ./pki/ca.crt ./pki/private/${CLIENT_USER}.key ./pki/issued/${CLIENT_USER}.crt  /tmp/openvpn/
      chmod a+r /tmp/openvpn/*
      ovpnclient_for_win 
      echo "Now also generate pkcs12 cert for client. "
      openssl pkcs12 -export -clcerts -in ./pki/issued/${CLIENT_USER}.crt -inkey ./pki/private/${CLIENT_USER}.key -out /tmp/openvpn/${CLIENT_USER}.p12 -passout pass:
      zip -j /tmp/pvpn-openvpn-${CLIENT_USER}certs.zip ./pki/ca.crt ./pki/issued/${CLIENT_USER}.crt ./pki/private/${CLIENT_USER}.key /tmp/openvpn/${CLIENT_USER}.p12 /tmp/openvpn/${CLIENT_USER}.ovpn
    else
       echo "Please manually put client ca,key,cert in client PC"
    fi


  else
#use ipsec to generte certs
    if [ -e /etc/ipsec.d/certs/servercert.pem ]; then
      if prompt-yesno "Strongswan server cert already exist, generate a new one?" "no" ; then
         NEED_SCERT="yes"
      else
         NEED_SCERT="no"
      fi
    fi

    if [ "yes" = "$NEED_SCERT" ]; then
        ipsec pki --gen --outform pem > /etc/ipsec.d/private/serverkey.pem
        ipsec pki --pub --in /etc/ipsec.d/private/serverkey.pem | ipsec pki --issue --cacert /etc/ipsec.d/cacerts/cacert.pem --cakey /etc/ipsec.d/private/cakey.pem --dn "C=CN,O=Palfort,CN=server" --san server --san dns:${SERVER_URL} --flag serverAuth --flag ikeIntermediate --outform pem > /etc/ipsec.d/certs/servercert.pem
        echo "Server cert have been generated"
    fi
    if [ -e /etc/ipsec.d/certs/clientcert.pem ]; then
      if prompt-yesno "client cert already exist, generate a new one?" "no" ; then
          echo "Please specify the username of client, use client- as prefix. It will keep original one and generate a new user cert"
      else
          ADD_CLIENT="no"
      fi
    fi
    if [ "yes" = "$ADD_CLIENT" ]; then
      CLIENT_USER=$(prompt "Please input the username of client:" "client")
      ipsec pki --gen --outform pem > /etc/ipsec.d/private/${CLIENT_USER}key.pem
      ipsec pki --pub --in /etc/ipsec.d/private/${CLIENT_USER}key.pem | ipsec pki --issue --cacert /etc/ipsec.d/cacerts/cacert.pem --cakey /etc/ipsec.d/private/cakey.pem --dn "C=CN,O=Palfort,CN=${CLIENT_USER}" --san client --outform pem > /etc/ipsec.d/certs/${CLIENT_USER}cert.pem
    fi
      
    if prompt-yesno "you've generated a client cert. Do you want to pack all client certs stuff for easy downloading" "yes" ; then
      WORK_DIR=$(pwd)
      cd /etc/ipsec.d/private
      mkdir -p /tmp/ipsec.d/private
      ls|grep -v cakey.pem|grep -v serverkey.pem|xargs -i cp -rp {} /tmp/ipsec.d/private/
      mkdir -p /tmp/ipsec.d/cacerts
      mkdir -p /tmp/ipsec.d/certs
      cp /etc/ipsec.d/cacerts/cacert.pem /tmp/ipsec.d/cacerts/
      cd /etc/ipsec.d/certs/
      ls|grep -v servercert.pem|xargs -i cp -rp {} /tmp/ipsec.d/certs/
      echo "pack ipsec pki client certs"
      cd /tmp
      echo "VIRTUALIP is  ${VIRTUALIP}"
      ipsecclient_from_server
      sync
      openssl pkcs12 -export -clcerts -in ./ipsec.d/certs/${CLIENT_USER}cert.pem -inkey ./ipsec.d/private/${CLIENT_USER}key.pem -out ./${CLIENT_USER}.p12 -passout pass: 
      zip -r pvpn-ipsec-${CLIENT_USER}certs.zip ./ipsec.d/private/${CLIENT_USER}key.pem ./ipsec.d/certs/${CLIENT_USER}cert.pem ./ipsec.d/cacerts/cacert.pem ./ipsec.conf ./ipsec.secrets

#if it's dualvpn
      if [ "dualvpn" = "$VPN_TYPE" ]; then
#check if server cert exist
        if [ -e /etc/openvpn/server.crt ]; then
          if prompt-yesno "Openvpn server cert already exist, generate a new one?" "no" ; then
            NEED_SCERT="yes"
          else
            NEED_SCERT="no"
          fi
        fi
        if [ "yes" = "$NEED_SCERT" ]; then


          echo "Copy to openvpn config file"
          cp /etc/ipsec.d/private/serverkey.pem /etc/openvpn/server.key
          cp /etc/ipsec.d/certs/servercert.pem /etc/openvpn/server.crt
          cp /etc/ipsec.d/cacerts/cacert.pem /etc/openvpn/ca.crt
          openssl pkcs12 -export -clcerts -in /etc/ipsec.d/certs/servercert.pem -inkey /etc/ipsec.d/private/serverkey.pem -out /etc/stunnel/server.p12 -passout pass:
          if [ -e /etc/openvpn/dh.pem ]; then
              if prompt-yesno "you've got dh.pem in PKI, use it?" "yes" ; then
                 echo "use current dh.pem"
                 NEEDDH="no"
              fi
          fi
          if [ "yes" = "$NEEDDH" ] ; then
            openssl dhparam -out dh.pem 2048
            mv dh.pem /etc/openvpn/
          fi
        fi
        mkdir -p /tmp/openvpn
        echo "Copy client cert to openvpn temp config folder"
        mv /tmp/ipsec.d/certs/${CLIENT_USER}cert.pem /tmp/openvpn/${CLIENT_USER}.crt
        mv /tmp/ipsec.d/private/${CLIENT_USER}key.pem /tmp/openvpn/${CLIENT_USER}.key
        ovpnclient_for_win
        sync
        echo "Now also generate a pkcs12 cert for client. "
#        openssl pkcs12 -export -clcerts -in /tmp/openvpn/client.crt -inkey /tmp/openvpn/client.key -out /tmp/client.p12 -passout pass:
        zip -j pvpn-openvpn-${CLIENT_USER}certs.zip ./${CLIENT_USER}.p12 ./openvpn/${CLIENT_USER}.ovpn /etc/openvpn/ca.crt ./openvpn/${CLIENT_USER}.crt ./openvpn/${CLIENT_USER}.key
      fi

# end of if dualvpn
      rm -rf /tmp/ipsec.d 
      cd $WORK_DIR
      echo "now in  ${WORK_DIR}"
    else
       echo "Please manually put client ca,key,cert in client PC pki"
       MANUALLY_DOWNLOAD="yes"
    fi

  fi
# put for downloads
#  if [ -e /etc/webfsd.conf ] ; then
  if [ "no" = "$MANUALLY_DOWNLOAD" ]; then
    echo "put in webfs for downloads"
    cp /tmp/pvpn*.zip /var/www/html/pvpn/

    echo "In linux, you can choose to autodownload and config clients. But please download from http://your-server-ip:8000/pvpn/ and put it in client configuration path in other OS"
    if [ openvpn = "$VPN_TYPE" ]||[ dualvpn = "$VPN_TYPE" ]; then
      echo "you have openvpn installed"
      mkdir -p /var/www/html/pvpn/openvpn
      cp /tmp/openvpn/* /var/www/html/pvpn/openvpn/
      echo "For openvpn, please put stunnel.conf in stunnel config and unzip pvpn-openvpn-clientcerts.zip to opevpn config path"
      rm -rf /tmp/openvpn /tmp/pvpn-o*.zip
    fi
    if [ strongswan = "$VPN_TYPE" ]||[ dualvpn = "$VPN_TYPE" ]; then
      echo "you have strongswan installed"
      mkdir -p /var/www/html/pvpn/strongswan
      cp /etc/ipsec.d/cacerts/cacert.pem /var/www/html/pvpn/strongswan/
      mv /tmp/${CLIENT_USER}.p12 /var/www/html/pvpn/strongswan/
      chmod a+r /var/www/html/pvpn/strongswan/${CLIENT_USER}.p12
      mv /tmp/ipsec.conf /var/www/html/pvpn/strongswan/
      mv /tmp/ipsec.secrets /var/www/html/pvpn/strongswan/
      rm -rf /tmp/pvpn-i*.zip /tmp/ipsec.*
    fi
  else
   echo "you need to download your client certs (in /tmp/) for the use in client PC"
  fi

}

ovpnclient_for_win() {
    echo "now generate windows client config"
    echo -n "" > /tmp/openvpn/stunnel.conf
    echo "[openvpn-localhost]" >> /tmp/openvpn/stunnel.conf
    echo "client=yes" >> /tmp/openvpn/stunnel.conf
    echo "accept = 127.0.0.1:11000" >> /tmp/openvpn/stunnel.conf
    echo "connect = ${SERVER_URL}:8443" >> /tmp/openvpn/stunnel.conf
#configure openvpn client for windows
    echo -n "" > /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "client" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "proto tcp" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "dev ${OVPN_INTERFACE}" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "ca ca.crt" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "cert ${CLIENT_USER}.crt" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "key ${CLIENT_USER}.key" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "remote 127.0.0.1 11000" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "resolv-retry infinite" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "dhcp-option DNS 1.1.1.1" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "nobind" >> /tmp/openvpn/${CLIENT_USER}.ovpn
    echo "${OVPN_COMPRESS}" >> /tmp/openvpn/${CLIENT_USER}.ovpn
}

ipsecclient_from_server() {
    echo -n "" > /tmp/ipsec.conf
    echo "config setup" >> /tmp/ipsec.conf
    echo "  # strictcrlpolicy=yes" >> /tmp/ipsec.conf
    echo "  # uniquyeids=no" >> /tmp/ipsec.conf
    echo "conn %default" >> /tmp/ipsec.conf
    echo "  keyexchange=ikev2" >> /tmp/ipsec.conf
    echo "#  ike=aes256-sha1-modp1024" >> /tmp/ipsec.conf


    echo "conn pvpn" >> /tmp/ipsec.conf
    echo "  left=%defaultroute" >> /tmp/ipsec.conf
    echo "  leftid=@${CLIENT_USER}" >> /tmp/ipsec.conf
    echo "  leftcert=${CLIENT_USER}cert.pem" >> /tmp/ipsec.conf
    if [ "yes" = "$VIRTUALIP" ]; then
      echo "  leftsourceip=%config" >> /tmp/ipsec.conf
    fi
    echo "  leftfirewall=yes" >> /tmp/ipsec.conf
    echo "  right=${SERVER_URL}" >> /tmp/ipsec.conf
    echo "  rightid=@server" >> /tmp/ipsec.conf
    if [ "yes" = "$VPN_INTERNET" ]; then
      echo "  rightsubnet=0.0.0.0/0" >> /tmp/ipsec.conf
      echo "  auto=add" >> /tmp/ipsec.conf
#      echo "conn local-net" >> /tmp/ipsec.conf
#      echo "  leftsubnet=%default" >> /tmp/ipsec.conf
    else
      echo "  rightsubnet=${SERVER_SUBNET}" >> /tmp/ipsec.conf
      echo "  auto=add" >> /tmp/ipsec.conf
#      if [ "yes" = "$VIRTUALIP" ]; then
#        echo "  rightsubnet=10.100.0.0/16" >> /tmp/ipsec.conf
#      else
#        echo "  rightsubnet=${SERVER_SUBNET}" >> /tmp/ipsec.conf
#      fi
    fi
#    echo "  auto=add" >> /tmp/ipsec.conf
    echo -n "" > /tmp/ipsec.secrets
    echo ": RSA ${CLIENT_USER}key.pem" >> /tmp/ipsec.secrets


}



ipsec_config() {
 if [ "server" = "$VPN_MODE" ]; then
    echo "you'll use ipsec pki"
    if [ -e /etc/ipsec.d/cacerts/cacert.pem ]; then
      if [ -e /etc/ipsec.d/private/cakey.pem ]; then
         if prompt-yesno "You've got a CA on PKI. Would you like to use it?" "yes" ; then
           echo "use current CA"
           NEEDPKICA="no"
         else
           echo "Re-initial PKI and generat a new CA"
         fi
      fi
    fi
    if [ "yes" = "$NEEDPKICA" ]; then
      InitPKI_buildCA
      sleep 1
    fi
    echo "now we have known CA is there, start to generate server certs now!"
    generate_certs
 fi
 ipsec_config_file
 if [ "dualvpn" = "$VPN_TYPE" ]; then
    ovpn_config_file
 fi
}


openvpn_config() {
  echo "you'll use openvpn and easyRSA as PKI tool"
  if [ "server" = "$VPN_MODE" ]; then
    echo "You'll configure opevpn server mode"
    cd /etc/openvpn/easyrsa
    echo "Now in /etc/openvpn/easyrsa"
    if  [ -e /etc/openvpn/easyrsa/pki/ca.crt ]; then
      if [ -e /etc/openvpn/easyrsa/pki/private/ca.key ]; then
        if prompt-yesno "You've got a CA on PKI. Would you like to use it?" "yes" ; then
          echo "use current CA"
          NEEDPKICA="no"
        else
          echo "Re-initial PKI and generat a new CA"
        fi
      fi
    fi
    if [ "yes" = "$NEEDPKICA" ] ; then
      InitPKI_buildCA
      sleep 1
      echo "copy ca.crt to config folder"
      cp  ./pki/ca.crt /etc/openvpn/
    fi
    echo "now we have known CA is there, start to generate server certs now!"
    generate_certs
  fi
    ovpn_config_file
}


ovpn_config_file() {
  if [ "server" = "$VPN_MODE" ] ; then
    echo "checking current config file"
    if [ -e /etc/stunnel/stunnel.conf ]; then
      if prompt-yesno "you've got a stunnel.conf,overwrite it?" "yes" ; then
        echo "Scripts will remove stunnel and openvpn config file first. "
        rm -rf /etc/stunnel/stunnel.conf
        KEEPSTUNNEL="no"
      else
        KEEPSTUNNEL="yes"
      fi
    fi

#configure stunnel server here
    if [ "$KEEPSTUNNEL" = "no" ]; then
      echo -n "" > /etc/stunnel/stunnel.conf
#   fetch_server_auth
      echo "cert=/etc/stunnel/server.p12" >> /etc/stunnel/stunnel.conf
      echo "client=no" >> /etc/stunnel.conf
      echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
      echo "accept = 8443" >> /etc/stunnel/stunnel.conf
      echo "connect = 127.0.0.1:11000" >> /etc/stunnel/stunnel.conf
    else
      echo "you've chosen to keep stunnel.con"
    fi
#configure openvpn server here
    if [ -e ${OVPN_CONFIG_SDIR}/server.conf ]; then
      if prompt-yesno "you've got a openvpn-server config file, overwrite it?" "yes" ; then
        rm -rf $OVPN_CONFIG_SDIR/server.conf
        KEEPOVPN_SCONFIG="no"
      else
        KEEPOVPN_SCONFIG="yes"
      fi
    fi
    if [ "$KEEPOVPN_SCONFIG" = "no" ]; then
      echo -n "" > $OVPN_CONFIG_SDIR/server.conf
      echo "port 11000" >> $OVPN_CONFIG_SDIR/server.conf
      echo "proto tcp" >> $OVPN_CONFIG_SDIR/server.conf
      echo "dev ${OVPN_INTERFACE}" >> $OVPN_CONFIG_SDIR/server.conf
      echo "ca /etc/openvpn/ca.crt" >> $OVPN_CONFIG_SDIR/server.conf
      echo "cert /etc/openvpn/server.crt" >> $OVPN_CONFIG_SDIR/server.conf
      echo "key /etc/openvpn/server.key" >> $OVPN_CONFIG_SDIR/server.conf
      echo "dh /etc/openvpn/dh.pem" >> $OVPN_CONFIG_SDIR/server.conf
      echo "" >> $OVPN_CONFIG_SDIR/server.conf
      echo "server 10.100.101.0 255.255.255.0" >> $OVPN_CONFIG_SDIR/server.conf
      echo "ifconfig-pool-persist $OVPN_LOG_DIR/ipp.txt" >> $OVPN_CONFIG_SDIR/server.conf
      echo "push \"redirect-gateway def1 bypass-dhcp\"" >> $OVPN_CONFIG_SDIR/server.conf
      echo "push \"dhcp-option DNS 1.1.1.1\"" >> $OVPN_CONFIG_SDIR/server.conf
      echo "push \"dhcp-option DNS 8.8.8.8\"" >> $OVPN_CONFIG_SDIR/server.conf
      echo "push \"route ${SERVER_URL} 255.255.255.255 net_gateway\"" >> $OVPN_CONFIG_SDIR/server.conf
      echo "client-to-client" >> $OVPN_CONFIG_SDIR/server.conf
      echo "duplicate-cn" >> $OVPN_CONFIG_SDIR/server.conf
      echo "keepalive 10 120" >> $OVPN_CONFIG_SDIR/server.conf
      echo "$OVPN_COMPRESS" >> $OVPN_CONFIG_SDIR/server.conf
      echo "max-clients 10" >>$OVPN_CONFIG_SDIR/server.conf
      echo ";user nobody" >> $OVPN_CONFIG_SDIR/server.conf
      echo ";group nogroup" >> $OVPN_CONFIG_SDIR/server.conf
      echo ";persist-key" >> $OVPN_CONFIG_SDIR/server.conf
      echo ";persist-tun" >> $OVPN_CONFIG_SDIR/server.conf
      echo "status $OVPN_LOG_DIR/openvpn-status.log" >> $OVPN_CONFIG_SDIR/server.conf
      echo "verb 3" >> $OVPN_CONFIG_SDIR/server.conf
      echo "mute 20" >> $OVPN_CONFIG_SDIR/server.conf
      echo "# explicit-exit-notify 1" >> $OVPN_CONFIG_SDIR/server.conf
      echo "openVPN server configuration finished"
    else
      echo "You've chosen to keep openvpn-server config file"
    fi

    if prompt-yesno "would you like to start the openvpn server after boot" "yes"; then
      systemctl enable $OVPN_SSERVICE
      systemctl start $OVPN_SSERVICE
      systemctl restart stunnel4
#      /etc/init.d/stunnel4 start
    else
      echo "You need to manually start your openvpn server by typing systemctl start openvpn-server@server"
    fi
    echo "You also need to open 8443 port in your server's firewall to enable client access"
  else
    echo "you'll configure stunnel4 and openvpn client mode now"
    echo "Scripts will remove stunnel and openvpn config file first. You can cancel it by typing ctrl+c If you dont want to proceed." 
    rm -rf /etc/stunnel/stunnel.conf
    rm -rf $OVPN_CONFIG_CDIR/ca.*
    echo "configuring stunnel.conf"
    echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
    echo "client=yes" >> /etc/stunnel/stunnel.conf
    echo "accept = 127.0.0.1:11000" >> /etc/stunnel/stunnel.conf
    echo "connect = ${SERVER_URL}:8443" >> /etc/stunnel/stunnel.conf
    echo "configuring openvpn client"
    CLIENT_USER=$(prompt "Please input the client username:" "client")
    rm -rf $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo -n "" > $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "client" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "proto tcp" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "dev ${OVPN_INTERFACE}" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "ca /etc/openvpn/ca.crt" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "cert /etc/openvpn/${CLIENT_USER}.crt" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "key /etc/openvpn/${CLIENT_USER}.key" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "remote 127.0.0.1 11000" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "resolv-retry infinite" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "nobind" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "$OVPN_COMPRESS" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo ";user nobody" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo ";group nobody" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "persist-key" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "persist-tun" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "mute 20" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "prepare scripts to auto setup routes that need to go via local gateway"
    rm -rf $OVPN_CONFIG_CDIR/nonvpn-routes.up
    rm -rf $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "script-security 2" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "up /etc/openvpn/${DNS_UPDATER}" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo "down /etc/openvpn/${DNS_UPDATER}" >> $OVPN_CONFIG_CDIR/${CLIENT_USER}.conf
    echo -n "" > $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "#!/bin/bash" >> $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "echo \"set routes for VPNserver and some local IPs that will go via local gateway\"" >> $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "LocalGW=\$(ip route | grep default | awk '{print \$3}')" >> $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "sleep 3"  >>  $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "ip route add 114.114.114.0/24 via \$LocalGW" >> $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "ip route add 101.231.59.0/24 via \$LocalGW" >> $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "ip route add 104.193.88.0/24 via \$LocalGW" >> $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo "ip route add ${SERVER_URL}/32 via \$LocalGW" >> $OVPN_CONFIG_CDIR/nonvpn-routes.up
    echo -n "" > $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "#!/bin/bash" >> $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "echo \"delete routes for VPNserver and some local IP that need go via local gateway\"" >> $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "sleep 3"  >>  $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "ip route del 114.114.114.0/24" >> $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "ip route del 101.231.59.0/24" >> $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "ip route del 104.193.88.0/24" >> $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "ip route del ${SERVER_URL}/32" >> $OVPN_CONFIG_CDIR/nonvpn-routes.down
    echo "chmod a+x $OVPN_CONFIG_CDIR/nonvpn-routes.*"
    chmod a+x $OVPN_CONFIG_CDIR/nonvpn-routes.*

    if prompt-yesno "would you like to auto start openvpn client service" "no" ; then
      systemctl enable $OVPN_CSERVICE
      echo "You've enable openvpn client service after boot. All trafic will go via vpn server by default configuration. "
    else
      systemctl disable $OVPN_CSERVICE
      echo "Please manually start openvpn client service by typing: systemctl start openvpn-client@client"
      echo "when you start the VPN service, all trafic will go via vpn server as default route as part of default configuration"
    fi 
    systemctl restart stunnel4
#    /etc/init.d/stunnel4 start
    echo "client configuration have been generated. you still need CA and certs in right place to start the openvpn client service. You can let scripts autodownload later"
  fi
}

ipsec_config_file() {
#configure ipsec herek
if prompt-yesno "Would you like to tunnel all  trafic to VPN server" "yes" ; then
    VPN_INTERNET="yes"
else
    VPN_INTERNET="no"
fi

if [ "server" = "$VPN_MODE" ] ; then
  if [ -e /etc/ipsec.conf ]; then
    if prompt-yesno "ipsec.conf already exist, would you like to keep it?" "no" ; then
      echo "You chose to keep original ipsec configure in server"
      KEEP_IPSEC_CONFIG="yes"
    else
      KEEP_IPSEC_CONFIG="no"
    fi
  fi
  if [ "no" = "$KEEP_IPSEC_CONFIG" ]; then
    echo "start to configure ipsec server side"
    #client user is default
    if [ "client" = "$CLIENT_USER" ]; then
      echo -n "" > /etc/ipsec.conf
      echo "config setup" >> /etc/ipsec.conf
      echo "  # strictcrlpolicy=yes" >> /etc/ipsec.conf
      echo "  uniqueids=never" >> /etc/ipsec.conf
      echo "conn %default" >> /etc/ipsec.conf
      echo "  left=%any" >> /etc/ipsec.conf
      echo "  leftsubnet=0.0.0.0/0" >> /etc/ipsec.conf
      echo "  leftcert=servercert.pem" >> /etc/ipsec.conf
      echo "  leftid=@server" >> /etc/ipsec.conf+
      echo "  # leftfirewall=yes" >> /etc/ipsec.conf
      echo "# IOS or android can use ikev1 and xauth psk" >> /etc/ipsec.conf
      echo "conn ikev1_psk_xauth" >> /etc/ipsec.conf
      echo "  keyexchange=ikev1" >> /etc/ipsec.conf
      echo "  leftauth=psk" >> /etc/ipsec.conf
      echo "  rightauth=psk" >> /etc/ipsec.conf
      echo "  rightauth2=xauth" >> /etc/ipsec.conf
      echo "  ike=aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024" >> /etc/ipsec.conf
      echo "  right=%any" >> /etc/ipsec.conf
      echo "  rightsourceip=10.100.100.0/24" >> /etc/ipsec.conf
      echo "  rightdns=1.1.1.1" >> /etc/ipsec.conf
      echo "  auto=add" >> /etc/ipsec.conf
      echo "# windows,linux,ikev2,cert" >> /etc/ipsec.conf
      echo "conn ikev2_cert" >> /etc/ipsec.conf
      echo "  keyexchange=ikev2" >> /etc/ipsec.conf
      echo "  ike=aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024" >> /etc/ipsec.conf
      echo "  rightauth=pubkey" >> /etc/ipsec.conf
      echo "  rightid=@client" >> /etc/ipsec.conf
      echo " rightcert=clientcert.pem" >> /etc/ipsec.conf
      if [ "yes" = "$VIRTUALIP" ]; then
        echo "  rightsourceip=10.100.100.0/24" >> /etc/ipsec.conf
      else
        RIGHT_SUBNET=$(prompt "Please input the client subnet:" "0.0.0.0/0")
      echo "  rightsubnet=${RIGHT_SUBNET}" >> /etc/ipsec.conf
      fi
      echo "  rightdns=1.1.1.1" >> /etc/ipsec.conf
      echo "  auto=add" >> /etc/ipsec.conf
      echo "# windows,IOS 9+, EAP" >> /etc/ipsec.conf
      echo "conn ikev2_eap" >> /etc/ipsec.conf
      echo "  keyexchange=ikev2" >> /etc/ipsec.conf
      echo "  ike=aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024" >> /etc/ipsec.conf
      echo "  esp=aes256-sha256,3des-sha1,aes256-sha1" >> /etc/ipsec.conf
      echo "  rekey=no" >> /etc/ipsec.conf
      echo "  leftauth=pubkey" >> /etc/ipsec.conf
      echo "  leftcert=servercert.pem" >> /etc/ipsec.conf
      echo "  leftsendcert=always" >> /etc/ipsec.conf
      echo "  rightauth=eap-mschapv2" >> /etc/ipsec.conf
      echo "  rightsendcert=never" >> /etc/ipsec.conf
      echo "  rightsourceip=10.100.100.0/24" >> /etc/ipsec.conf
      echo "  eap_identity=%any" >> /etc/ipsec.conf
      echo "  fragmentation=yes" >> /etc/ipsec.conf
      echo "  rightdns=1.1.1.1" >> /etc/ipsec.conf
      echo "  auto=add" >> /etc/ipsec.conf
    else
    #client user is new one , add this part into server ipsec config file
      if cat /etc/ipsec.conf |grep "${CLIENT_USER}">/dev/null ; then
        echo "This user is already configured"
      else
        echo "# additional client ikev2 cert support" >> /etc/ipsec.conf   
        echo "conn ikev2_cert_${CLIENT_USER}" >> /etc/ipsec.conf
        echo "  keyexchange=ikev2" >> /etc/ipsec.conf
        echo "  ike=aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024" >> /etc/ipsec.conf
        echo "  rightid=@${CLIENT_USER}" >> /etc/ipsec.conf
        echo "  rightcert=${CLIENT_USER}cert.pem" >> /etc/ipsec.conf

        if [ "yes" = "$VIRTUALIP" ]; then
          echo "  rightsourceip=10.100.100.0/24" >> /etc/ipsec.conf
        else
          RIGHT_SUBNET=$(prompt "Please input the client subnet:" "0.0.0.0/0")
        echo "  rightsubnet=${RIGHT_SUBNET}" >> /etc/ipsec.conf
        fi
        echo "  rightdns=1.1.1.1" >> /etc/ipsec.conf
        echo "  auto=add" >> /etc/ipsec.conf
 
      fi
    fi
    echo "now configuring vpn authentication method"
    echo -n "" > /etc/ipsec.secrets
    echo ": RSA serverkey.pem " >> /etc/ipsec.secrets
    echo ": PSK \"pvpnpassword\"" >> /etc/ipsec.secrets
    echo "robin %any : XAUTH \"pvpnpassword\"" >> /etc/ipsec.secrets
    echo "robin %any : EAP \"pvpnpassword\"" >> /etc/ipsec.secrets
    echo "ipsec configuration is ready to work now,please remember to open server's 500,4500 port and run ipsec restart before you can set up ipsec tunnel"
  fi
else
    CLIENT_USER=$(prompt "Please input the client username:" "client")
    CLIENT_LSUBNET=$(ip route |grep -v -w default| awk '/dev/ {print $1}' | head -1)
    echo "start to configure ipsec client side"
    echo -n "" > /etc/ipsec.conf
    echo "config setup" >> /etc/ipsec.conf
    echo "  # strictcrlpolicy=yes" >> /etc/ipsec.conf
    echo "  # uniqueids=no" >> /etc/ipsec.conf
    echo "conn %default" >> /etc/ipsec.conf
    echo "  keyexchange=ikev2" >> /etc/ipsec.conf
    echo "#  ike=aes256-sha1-modp1024" >> /etc/ipsec.conf
    echo "conn pvpn" >> /etc/ipsec.conf
    echo "  left=%defaultroute" >> /etc/ipsec.conf
    echo "  leftid=@${CLIENT_USER}" >> /etc/ipsec.conf
    echo "  leftcert=${CLIENT_USER}cert.pem" >> /etc/ipsec.conf
    if [ "yes" = "$VIRTUALIP" ]; then
      echo "  leftsourceip=%config" >> /etc/ipsec.conf
    fi
    echo "  leftfirewall=yes" >> /etc/ipsec.conf
    echo "  right=${SERVER_URL}" >> /etc/ipsec.conf
    echo "  rightid=@server" >> /etc/ipsec.conf
    if [ "yes" = "$VPN_INTERNET" ]; then
      echo "  rightsubnet=0.0.0.0/0" >> /etc/ipsec.conf
      echo "  auto=add" >> /etc/ipsec.conf
      echo "conn local-net" >> /etc/ipsec.conf
      echo "  leftsubnet=${CLIENT_LSUBNET}" >> /etc/ipsec.conf
      echo "  rightsubnet=${CLIENT_LSUBNET}" >> /etc/ipsec.conf
      echo "  authby=never" >> /etc/ipsec.conf
      echo "  type=pass" >> /etc/ipsec.conf
      echo "  auto=route" >> /etc/ipsec.conf 
     else
        RIGHT_SUBNET=$(prompt "Please input the server subnet:" "0.0.0.0/0")
        echo "  rightsubnet=${RIGHT_SUBNET}" >> /etc/ipsec.conf
        echo "  auto=add" >> /etc/ipsec.conf
    fi
    echo "now configuring VPN authenticaion method"
    echo -n "" > /etc/ipsec.secrets
    echo ": RSA ${CLIENT_USER}key.pem" >> /etc/ipsec.secrets
    echo "strongswan configuration finished, you can start ipsec vpn at client side with command: ipsec up pvpn"
    echo "Please download http://$SERVER_URL:8000/pvpn/pvpn-ipsec-clientcerts.zip and put it in the right place of your client"
    echo "To extract to the right place: sudo unzip pvpn-ipsec-clientcerts.zip -d /etc/"
fi

}


ipsec_install() {
  echo "about to install both strongswan and openvpn"
  echo "apt install -y strongswan strongswan-pki" | tee -a /var/log/pvpn_install.log
  apt install -y strongswan
  apt install -y strongswan-pki 

  if prompt-yesno "Would you like IPsec VPN server to allocate virtual IP for clients" yes; then
    VIRTUALIP="yes"
  else
    VIRTUALIP="no"
  fi


  if [ "dualvpn" = "$VPN_TYPE" ]; then
    openvpn_install
  fi
  if [ "server" = "$VPN_MODE" ]; then
    echo "try to get the server subnet"
    apt install -y libcharon-extra-plugins
    SERVER_SUBNET=$(ip -o addr | grep global | awk '/^[0-9]/ {print gensub(/(.*)/,"\\1","g",$4)}'|head -1)
    if [ -z "$SERVER_SUBNET" ]; then
      SERVER_SUBNET="0.0.0.0/0"
    fi
  fi
}

openvpn_install()  {
#for openvpn sole installation, need to  install easyrsa as well
#check if openvpn and stunnel have already installed and set flag
  OVPN_EXIST="no"
  STUNNEL_EXIST="no"
  EASYRSA_EXIST="no"
  if [ -e /etc/stunnel ] ; then
   if prompt-yesno "stunnel already installed,type yes if you want to reinstall it anyway?" "no" ; then
     echo "stunnel4 will be reinstalled"
   else
     STUNNEL_EXIST="yes"
     echo "Scripts will use current stunnel4 installation"
   fi
  fi
  if [ -e /etc/openvpn ] ; then
   if prompt-yesno "openvpn already installed,type yes if you want to reinstall it anyway?" "no" ; then
     echo "openvpn will be reinstalled"
   else
     OVPN_EXIST="yes"
     echo "Scripts will use current openvpn installation"
   fi
  fi
  if [ "no" = "$STUNNEL_EXIST" ] ; then
    echo "apt install -y stunnel4 " | tee -a /var/log/pvpn_install.log
    apt install -y stunnel4
  fi
  if [ "no" = "$OVPN_EXIST" ] ; then
    echo "apt install -y openvpn resolvconf" | tee -a /var/log/pvpn_install.log
    apt install -y openvpn resolvconf
  fi
 
  echo "Check chosen vpn type and then install easyrsa3 if it's openvpn solo installation"
  if [ "openvpn" = "$VPN_TYPE" ]; then
    if [ "server" = "$VPN_MODE" ]; then
       echo "you're about to install easyRSA3 as PKI tool"
       if [ -e /etc/openvpn/easyrsa ]; then
         if prompt-yesno "easyrsa PKI already there, type yes if you want to remove it first and then download a new one?" "no" ; then
           rm -rf /etc/openvpn/easyrsa*
           rm -rf  /tmp/EasyRSA*
         else  
           EASYRSA_EXIST="yes"
           echo "you've chosen to use existing easyrsa as PKI"
         fi
       fi
       if [ "no" = "$EASYRSA_EXIST" ] ; then
         echo "Download EasyRSA-{$EASYRSA_VERSION}.tgz via wget and then extract it into /etc/openvpn/easyrsa" | tee -a /var/log/pvpn_install.log
         wget -P /tmp/ https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz
         tar xvf /tmp/EasyRSA-${EASYRSA_VERSION}.tgz -C /etc/openvpn/
         mv /etc/openvpn/EasyRSA-${EASYRSA_VERSION} /etc/openvpn/easyrsa
         rm -rf /tmp/EasyRSA*.tgz
       fi
    fi

  else
    echo "you'll use stongswan PKI in openvpn."
  fi
  if [ "client" = "$VPN_MODE" ]; then
    echo "Now try to install openvpn dns scripts "
    apt install openvpn-systemd-resolved -y
  fi

  echo "configure stunnel4 auto-start here"
  if prompt-yesno "would you like to enable stunnel autorun after boot" "yes"; then
    sed -i "s/^ENABLED=0/ENABLED=1/" /etc/default/stunnel4
    echo "stunnel4 autostart enabled"
  else
    echo "you need to manual start stunnel service"
  fi
   
}


##### function block end #####

#Installation scripts start here. First check if it's root privilege. if not, aborted. 

#To install VPN server or VPN client. Generally VPN server have a public IP and it will work as a responder, while VPN client will act as initiator.
#VPN server can also set up CA system or use an exist one. 
EASYRSA_VERSION="3.1.0"
check_root
handle_args "$@"
set_umask
assert_on_terminal
prepare_installation_paras
confirm_install
confirm_setting
finish_pvpn
}

# Now that we know the whole script has downloaded, run it.
_ "$0" "$@"
