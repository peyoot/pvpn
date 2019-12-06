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
#check out ubuntu version
UBUNTU_VERSION='lsb_release --release | cut -f2'
#set necessary variables
NEEDPKICA="yes"
NEEDDH="yes"
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
    echo ""
    CHOSEN_VPN_MODE=$(prompt-numeric "How are you going to install?" "1")
  fi
  if [ "1" = "$CHOSEN_VPN_MODE" ] ; then
    echo "Select VPN server mode" | tee /var/log/pvpn_install.log
    VPN_MODE="server"
  else
    echo "Select VPN client mode " | tee -a /var/log/pvpn_install.log
    VPN_MODE="client"
  fi
    
  if [ -z "${CHOSEN_VPN_TYPE:-}" ]; then
    echo "You can:"
    echo ""
    echo "1. Install openvpn+stunnel only and use easyrsa3 as PKI( enter to accept this default)"
    echo "2. Install both strongswan and openvpn, use strongswan PKI tool "
    echo ""
    CHOSEN_VPN_TYPE=$(prompt-numeric "Please choose which vpn type you're about to install?" "1")
  fi
  if [ "1" = "$CHOSEN_VPN_TYPE" ] ; then
    echo "Select openvpn over stunnel" | tee -a /var/log/pvpn_install.log
    VPN_TYPE="openvpn"
  else
    echo "Select both openvpn/stunnel and strongswan VPN" | tee -a /var/log/pvpn_install.log
    VPN_TYPE="dualvpn"
  fi
fi
}

confirm_install() {
  echo "sctips are about to install software you choose"
  echo "you've chosen $VPN_TYPE"
  echo "prepare some software packages for scripts to use"
  echo "apt update" | tee -a /var/log/pvpn_install.log 
  apt update
  if [ ! -e /usr/bin/zip ] ; then
     echo "apt install -y zip" | tee -a /var/log/pvpn_install.log
     apt install -y zip
  fi
#  apt install -y net-tools
  if [ "server" = "$VPN_MODE" ] ; then
    if prompt-yesno "Would you like to install webfs so that scripts can help you to generate client certs download URL?" "yes" ; then
        echo "webfs will be installed.please wait...."
        echo "apt install -y webfs"
        apt install -y webfs
        echo "sleep 1"
        sleep 1
        echo "mkdir -p /var/www/html" | tee -a /var/log/pvpn_install.log
        mkdir -p /var/www/html
        echo "create /var/www/html for webfs"
    else
        echo "you've bypass the webfs installation. You'll need to manually copy client certs to client side later"
    fi
  fi
  
  if [ "openvpn" = "$VPN_TYPE" ] ; then
    openvpn_install
  else
    dualvpn_install
  fi
}


confirm_setting() {
  echo "sctips are about to setup software based on your choise"
  echo "you've chosen $VPN_TYPE"
  if [ "openvpn" = "$VPN_TYPE" ] ; then
    openvpn_config
  else
    dualvpn_config
  fi
}

use_existingCA() {
  if [ "openvpn" = "$VPN_TYPE" ] ; then
    CA_FILE="/etc/openvpn/ca.crt"
  else 
    CA_FILE="/etc/ipsec.d/cacerts/ca.crt"
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
    echo "about to build CA"
    ./easyrsa build-ca nopass
    sleep 1
    echo "CA has been generated by EASYRSA!"
  else
    echo "Initial ipsec pki and build CA now"
    ipsec pki --gen --outform pem > /etc/ipsec.d/private/cakey.pem
    ipsec pki --self --in /etc/ipsec.d/private/cakey.pem --dn "C=CN,O=Palfort,CN=PVPN CA" --ca --outform pem > /etc/ipsec.d/cacerts/cacert.pem
    echo "CA key and CA cert generated"

  fi
}

dualvpn_config() {
   echo "you'll use ipsec pki"
   if [ -e /etc/ipsec.d/cacerts/ca.crt ] ; then
      if prompt-yesno "You've got a CA on PKI. Would you like to use it?" "yes" ; then
        echo "use current CA"
        NEEDPKICA="no"
      else
        echo "Re-initial PKI and generat a new CA"
      fi
   fi
   if [ "yes" = "$NEEDPKICA" ] ; then
      InitPKI_buildCA
      sleep 1
   fi
    echo "now we have known CA is there, start to generate server certs now!"
    ipsec pki --gen --outform pem > /etc/ipsec.d/private/serverkey.pem
    ipsec pki --pub --in /etc/ipsec.d/private/serverkey.pem | ipsec pki --issue --cacert /etc/ipsec.d/cacerts/cacert.pem --cakey /etc/ipsec.d/private/cakey.pem --dn "C=CN,O=Palfort,CN=server" --san server --flag serverAuth --flag ikeIntermediate --outform pem > /etc/ipsec.d/certs/servercert.pem
    echo "Server cert has been generated now"
    echo "Now Create client cert,Please input username if you would like to generate specific cert"
    CLIENT_USER=$(prompt "Please input the username of client:" "client")
    ipsec pki --gen --outform pem > /etc/ipsec.d/private/${CLIENT_USER}key.pem
    ipsec pki --pub --in /etc/ipsec.d/private/${CLIENT_USER}key.pem | ipsec pki --issue --cacert /etc/ipsec.d/cacerts/cacert.pem --cakey /etc/ipsec.d/private/cakey.pem --dn "C=CN,O=Palfort,CN=${CLIENT_USER}" --san client --outform pem > /etc/ipsec.d/certs/${CLIENT_USER}cert.pem
    echo "You've generated the client cert. Scripts will help you pack it"
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
    zip -r client-ipsec.zip ./ipsec.d/*
    rm -rf /tmp/ipsec*
    openssl dhparam -out dh.pem 2048
    zip -j clientcerts.zip ./dh.pem ./ipsec.d/cacerts/ca.crt ./ipsec.d/certs/* ./ipsec.d/private/*
    cd $WORK_DIR
    echo "now in  ${WORK_DIR}"

}


openvpn_config() {
  echo "you'll use openvpn and easyRSA as PKI tool"
  if [ "server" = "$VPN_MODE" ] ; then
    echo "You'll configure opevpn server mode"
    cd /etc/openvpn/easyrsa
    echo "Now in /etc/openvpn/easyrsa"
    if  [ -e /etc/openvpn/ca.crt ] ; then
      if prompt-yesno "You've got a CA on PKI. Would you like to use it?" "yes" ; then
        echo "use current CA"
        NEEDPKICA="no"
      else
        echo "Re-initial PKI and generat a new CA"
      fi
    fi
    if [ "yes" = "$NEEDPKICA" ] ; then
      InitPKI_buildCA
      sleep 1
      echo "copy ca.crt to config folder"
      cp  ./pki/ca.crt /etc/openvpn/
    fi
    echo "now we have known CA is there, start to generate server certs now!"
    ./easyrsa gen-req server nopass
    sleep 1
    ./easyrsa sign server server
    echo "copy server key and cert to config folder"
    cp  ./pki/private/server.key ./pki/issued/server.crt  /etc/openvpn/
    if [ -e /etc/openvpn/dh.pem ] ; then
        if prompt-yesno "you've got dh.pem in PKI, use it?" "yes" ; then
           echo "use current dh.pem"
           NEEDDH="no"
        fi
    fi
    if [ "yes" = "$NEDDDH" ] ; then
      ./easyrsa gen-dh
      echo "copy dh to config folder"
      cp ./pki/dh.pem /etc/openvpn/
    fi
    sleep 3
    echo "server cert have been generated. Scripts will help you generate a client cert which you can copy to your client PC"
    echo "you can always generate specific user certs in server's PKI system by yourself later."
    ./easyrsa gen-req client nopass
    ./easyrsa sign client client
    if prompt-yesno "you've generated a client cert. Do you want to pack all client certs stuff for easy downloading" "yes" ; then
      echo "zip ca.crt client.key,client.crt to clientcerts.zip"
      cp  ./pki/ca.crt ./pki/private/client.key ./pki/issued/client.crt  /tmp/
      zip -j /tmp/clientcerts.zip /tmp/ca.crt /tmp/client.crt /tmp/client.key
      if [ -e /var/www/html ] ; then
        echo "put in webfs for downloads"
        cp /tmp/clientcerts.zip /var/www/html/
        echo "Please download from http://your-server-ip:8000/clientcerts.zip"
        rm -rf  /tmp/ca.crt /tmp/client*
      else
       echo "you need to download your client certs (/tmp/clientcerts.zip) for the use in client PC"
      fi
    else
       echo "Please manually put client ca,key,cert in client PC"
    fi
    echo "start to configure stunnel4 and openvpn server mode"
    echo "copy server key and cert for stunnel4"
    cp /etc/openvpn/server.crt /etc/stunnel/
    cp /etc/openvpn/server.key /etc/stunnel/

    if [ "18.04" = "$UBUNTU_VERSION" ]; then
      OVPN_CONFIG_DIR="/etc/openvpn/server"
      OVPN_SERVICE="openvpn-server@server"
      OVPN_COMPRESS="compress lz4-v2"
      OVPN_LOG_DIR="/var/log/openvpn"
    else 
      OVPN_CONFIG_DIR="/etc/openvpn"
      OVPN_SERVICE="openvpn@server"
      OVPN_COMPRESS="comp-lzo"
      OVPN_LOG_DIR="/var/log"
    fi


#configure stunnel server here
    echo "Scripts will remove stunnel and openvpn config file first. " 
    rm -rf /etc/stunnel/stunnel.conf
    rm -rf $OVPN_CONFIG_DIR/server.conf
    echo -n "" > /etc/stunnel/stunnel.conf
#   fetch_server_auth
    echo "cert=/etc/stunnel/server.crt" >> /etc/stunnel/stunnel.conf
    echo "key=/etc/stunnel/server.key" >> /etc/stunnel/stunnel.conf
    echo "client=no" >> /etc/stunnel.conf
    echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
    echo "accept = 8443" >> /etc/stunnel/stunnel.conf
    echo "connect = 127.0.0.1:11000" >> /etc/stunnel/stunnel.conf
#configure openvpn server here
    echo -n "" > $OVPN_CONFIG_DIR/server.conf
    echo "port 11000" >> $OVPN_CONFIG_DIR/server.conf
    echo "proto tcp" >> $OVPN_CONFIG_DIR/server.conf
    echo "dev tap" >> $OVPN_CONFIG_DIR/server.conf
    echo "ca /etc/openvpn/ca.crt" >> $OVPN_CONFIG_DIR/server.conf
    echo "cert /etc/openvpn/server.crt" >> $OVPN_CONFIG_DIR/server.conf
    echo "key /etc/openvpn/server.key" >> $OVPN_CONFIG_DIR/server.conf
    echo "dh /etc/openvpn/dh.pem" >> $OVPN_CONFIG_DIR/server.conf
    echo "" >> $OVPN_CONFIG_DIR/server.conf
    echo "server 10.8.0.0 255.255.255.0" >> $OVPN_CONFIG_DIR/server.conf
    echo "ifconfig-pool-persist $OVPN_LOG_DIR/ipp.txt" >> $OVPN_CONFIG_DIR/server.conf
    echo "push \"redirect-gateway def1 bypass-dhcp\"" >> $OVPN_CONFIG_DIR/server.conf
    echo "push \"dhcp-option DNS 208.67.222.222\"" >> $OVPN_CONFIG_DIR/server.conf
    echo "client-to-client" >> $OVPN_CONFIG_DIR/server.conf
    echo "duplicate-cn" >> $OVPN_CONFIG_DIR/server.conf
    echo "keepalive 10 120" >> $OVPN_CONFIG_DIR/server.conf
    echo "$OVPN_COMPRESS" >> $OVPN_CONFIG_DIR/server.conf
    echo "max-clients 10" >>$OVPN_CONFIG_DIR/server.conf
    echo "# user nobody" >> $OVPN_CONFIG_DIR/server.conf
    echo "# group nobody" >> $OVPN_CONFIG_DIR/server.conf
    echo "persist-key" >> $OVPN_CONFIG_DIR/server.conf
    echo "persist-tun" >> $OVPN_CONFIG_DIR/server.conf
    echo "status $OVPN_LOG_DIR/openvpn-status.log" >> $OVPN_CONFIG_DIR/server.conf
    echo "verb 3" >> $OVPN_CONFIG_DIR/server.conf
    echo "mute 20" >> $OVPN_CONFIG_DIR/server.conf
    echo "# explicit-exit-notify 1" >> $OVPN_CONFIG_DIR/server.conf
    echo "openVPN server configuration finished"
    if prompt-yesno "would you like to start the openvpn server after boot" "yes"; then
      systemctl enable $OVPN_SERVICE
    else
      echo "You need to manually start your openvpn server by typing systemctl start openvpn-server@server"
    fi
  else
    echo "you'll configure stunnel4 and openvpn client mode now"
    echo "Scripts will remove stunnel and openvpn config file first. You can cancel it by typing ctrl+c If you dont want to proceed." 
    if [ "18.04" = "$UBUNTU_VERSION" ]; then
      OVPN_CONFIG_DIR="/etc/openvpn/client"
      OVPN_SERVICE="openvpn-client@client"
      OVPN_COMPRESS="compress lz4-v2"
    else
      OVPN_CONFIG_DIR="/etc/openvpn"
      OVPN_SERVICE="openvpn@client"
      OVPN_COMPRESS="comp-lzo"
    fi
    rm -rf /etc/stunnel/stunnel.conf
    rm -rf $OVPN_CONFIG_DIR/server.conf
    echo "configuring stunnel.conf"
    echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
    echo "client=yes" >> /etc/stunnel/stunnel.conf
    echo "accept = 127.0.0.1:11000" >> /etc/stunnel/stunnel.conf
    SERVER_URL=$(prompt "Please input the openvpn server IP:" "")
    echo "connect = ${SERVER_URL}:8443" >> /etc/stunnel/stunnel.conf
    echo "configuring openvpn client"
    echo -n "" > $OVPN_CONFIG_DIR/client.conf
    echo "client" >> $OVPN_CONFIG_DIR/client.conf
    echo "proto tcp" >> $OVPN_CONFIG_DIR/client.conf
    echo "dev tap" >> $OVPN_CONFIG_DIR/client.conf
    echo "ca /etc/openvpn/ca.crt" >> $OVPN_CONFIG_DIR/client.conf
    echo "cert /etc/openvpn/client.crt" >> $OVPN_CONFIG_DIR/client.conf
    echo "key /etc/openvpn/client.key" >> $OVPN_CONFIG_DIR/client.conf
    echo "remote 127.0.0.1 11000" >> $OVPN_CONFIG_DIR/client.conf
    echo "resolv-retry infinite" >> $OVPN_CONFIG_DIR/client.conf
    echo "nobind" >> $OVPN_CONFIG_DIR/client.conf
    echo "$OVPN_COMPRESS" >> $OVPN_CONFIG_DIR/client.conf
    echo "# user nobody" >> $OVPN_CONFIG_DIR/client.conf
    echo "# group nobody" >> $OVPN_CONFIG_DIR/client.conf
    echo "persist-key" >> $OVPN_CONFIG_DIR/client.conf
    echo "persist-tun" >> $OVPN_CONFIG_DIR/client.conf
    echo "mute 20" >> $OVPN_CONFIG_DIR/client.conf
    echo "prepare scripts to auto setup routes that need to go via local gateway"
    rm -rf $OVPN_CONFIG_DIR/nonvpn-routes.up
    rm -rf $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "script-security 2" >> $OVPN_CONFIG_DIR/client.conf
    echo "up $OVPN_CONFIG_DIR/nonvpn-routes.up" >> $OVPN_CONFIG_DIR/client.conf
    echo "down $OVPN_CONFIG_DIR/nonvpn-routes.down" >> $OVPN_CONFIG_DIR/client.conf
    echo -n "" > $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "#!/bin/bash" >> $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "echo \"set routes for VPNserver and some local IPs that will go via local gateway\"" >> $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "LocalGW=\$(ip route | grep default | awk '{print \$3}')" >> $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "sleep 3"  >>  $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "ip route add 114.114.114.0/24 via \$LocalGW" >> $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "ip route add 101.231.59.0/24 via \$LocalGW" >> $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "ip route add 104.193.88.0/24 via \$LocalGW" >> $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo "ip route add ${SERVER_URL}/32 via \$LocalGW" >> $OVPN_CONFIG_DIR/nonvpn-routes.up
    echo -n "" > $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "#!/bin/bash" >> $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "echo \"delete routes for VPNserver and some local IP that need go via local gateway\"" >> $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "sleep 3"  >>  $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "ip route del 114.114.114.0/24" >> $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "ip route del 101.231.59.0/24" >> $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "ip route del 104.193.88.0/24" >> $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "ip route del ${SERVER_URL}/32" >> $OVPN_CONFIG_DIR/nonvpn-routes.down
    echo "chmod a+x $OVPN_CONFIG_DIR/nonvpn-routes.*"
    chmod a+x $OVPN_CONFIG_DIR/nonvpn-routes.*

    if prompt-yesno "would you like to auto start openvpn client service" "no" ; then
      systemctl enable $OVPN_SERVICE
      echo "You've enable openvpn client service after boot.with the default configured feature,all trafic will go via vpn server"
      echo "Please manually start openvpn client service by typing: systemctl start openvpn-client@client"
    else
      systemctl disable $OVPN_SERVICE
      echo "Please manually start openvpn client service by typing: systemctl start openvpn-client@client"
      echo "when you start the VPN service, all trafic will go via vpn server as default route"
    fi 
    echo "please put your ca/client certs into /etc/openvpn/ before you can use the openvpn client service"
    echo "If you download clientcerts.zip from http://$SERVER_URL:8000/, just run: sudo unzip -j clientcerts.zip -d /etc/openvpn/"
    echo "In ubuntu 18.04 you can use systemctl enable/disable openvpn-client@client to add it into system service and auto run after next boot"
    echo "or you can manually start openvpn by input: openvpn /etc/openvpn/client.conf (Ubuntu 16.04) or openvpn /etc/openvpn/client/client.conf (Ubuntu 18.04)"
  fi
}


dualvpn_install() {
  echo "about to install both strongswan and openvpn"
  echo "apt install -y strongswan" | tee -a /var/log/pvpn_install.log
  apt install -y strongswan 
  openvpn_install
  echo "apt install -y strongswan-pki" | tee -a /var/log/pvpn_install.log
  apt install -y strongswan-pki

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
    echo "apt install -y openvpn" | tee -a /var/log/pvpn_install.log
    apt install -y openvpn
  fi
 
 echo "Check chosen vpn type and then install easyrsa3 if it's openvpn solo installation"
  if [ "openvpn" = "$VPN_TYPE" ] ; then
     echo "you're about to install easyRSA3 as PKI tool"
     if [ -e /etc/openvpn/easyrsa ] ; then
       if prompt-yesno "easyrsa PKI already there, type yes if you want to remove it first and then download a new one?" "no" ; then
         rm -rf /etc/openvpn/easyrsa*
         rm -rf  /tmp/EasyRSA*
       else  
         EASYRSA_EXIST="yes"
         echo "you've chosen to use existing easyrsa as PKI"
       fi
     fi
     if [ "no" = "$EASYRSA_EXIST" ] ; then
       echo "Download EasyRSA-unix-{$EASYRSA_VERSION}.tgz via wget and then extract it into /etc/openvpn/easyrsa" | tee -a /var/log/pvpn_install.log
       wget -P /tmp/ https://github.com/OpenVPN/easy-rsa/releases/download/${EASYRSA_VERSION}/EasyRSA-unix-${EASYRSA_VERSION}.tgz
       tar xvf /tmp/EasyRSA-unix-${EASYRSA_VERSION}.tgz -C /etc/openvpn/
       mv /etc/openvpn/EasyRSA-${EASYRSA_VERSION} /etc/openvpn/easyrsa
     fi
  else
    echo "you'll use stongswan PKI in openvpn."
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
EASYRSA_VERSION="v3.0.6"
check_root
handle_args "$@"
set_umask
assert_on_terminal
prepare_installation_paras
confirm_install
confirm_setting
}

# Now that we know the whole script has downloaded, run it.
_ "$0" "$@"
