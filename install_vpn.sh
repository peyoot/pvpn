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
  apt install -y net-tools
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
    CA_FILE="/etc/openvpn/easyrsa3/pki/ca.crt"
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
  fi
}



openvpn_config() {
  NEEDPKICA="yes"
  echo "you'll use openvpn and easyRSA as PKI tool"
  if [ "server" = "$VPN_MODE" ] ; then
    echo "You'll configure opevpn server mode"
    cd /etc/openvpn/easyrsa
    echo "Now in /etc/openvpn/easyrsa"
    if  [ -e /etc/openvpn/easyrsa/pki/ca.crt ] ; then
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
    ./easyrsa gen-req server nopass
    sleep 1
    ./easyrsa sign server server
    if [ -e /etc/openvpn/easyrsa/pki/dh.pem ] ; then
        if prompt-yesno "you've got dh.pem in PKI, use it?" "yes" ; then
           echo "use current dh.pem"
        else 
           ./easyrsa gen-dh
        fi
     else
        ./easyrsa gen-dh
    fi
    sleep 3
    echo "server cert have been generated. Scripts will help you generate a client cert which you can copy to your client PC"
    echo "you can always generate specific user certs in server's PKI system by yourself later."
    ./easyrsa gen-req client nopass
    ./easyrsa sign client client
    if prompt-yesno "you've generated a client cert. Do you want to pack all client certs stuff for easy downloading" "yes" ; then
      echo "zip ca.crt client.key,client.crt to clientcerts.zip"
      zip /tmp/clientcerts.zip ./pki/ca.crt ./pki/private/client.key ./pki/issued/client.crt
      if [ -e /var/www/html ] ; then
        echo "put in webfs for downloads"
        cp /tmp/clientcerts.zip /var/www/html/
        echo "Please download from http://your-server-ip:8000/clientcerts.zip"
        rm -rf /tmp/clientcerts.zip
      else
       echo "you need to download your client certs (/tmp/clientcerts.zip) for the use in client PC"
      fi
    else
       echo "Please manually put client ca,key,cert in client PC"
    fi
    echo "start to configure stunnel4 and openvpn server mode"
    echo "copy server key and cert for stunnel4"
    cp /etc/openvpn/easyrsa/pki/issued/server.crt /etc/stunnel/
    cp /etc/openvpn/easyrsa/pki/private/server.key /etc/stunnel/
#configure stunnel server here
    echo "Scripts will remove stunnel and openvpn config file first. " 
    rm -rf /etc/stunnel/stunnel.conf
    rm -rf /etc/openvpn/server/server.conf
    echo -n "" > /etc/stunnel/stunnel.conf
#   fetch_server_auth
    echo "cert=/etc/stunnel/server.crt" >> /etc/stunnel/stunnel.conf
    echo "key=/etc/stunnel/server.key" >> /etc/stunnel/stunnel.conf
    echo "client=no" >> /etc/stunnel.conf
    echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
    echo "accept = 8443" >> /etc/stunnel/stunnel.conf
    echo "connect = 127.0.0.1:11000" >> /etc/stunnel/stunnel.conf
#configure openvpn server here
    echo -n "" > /etc/openvpn/server/server.conf
    echo "port 11000" >> /etc/openvpn/server/server.conf
    echo "proto tcp" >> /etc/openvpn/server/server.conf
    echo "dev tap" >> /etc/openvpn/server/server.conf
    echo "ca /etc/openvpn/easyrsa/pki/ca.crt" >> /etc/openvpn/server/server.conf
    echo "cert /etc/openvpn/easyrsa/pki/issued/server.crt" >> /etc/openvpn/server/server.conf
    echo "key /etc/openvpn/easyrsa/pki/private/server.key" >> /etc/openvpn/server/server.conf
    echo "dh /etc/openvpn/easyrsa/pki/dh.pem" >> /etc/openvpn/server/server.conf
    echo "" >> /etc/openvpn/server/server.conf
    echo "server 10.8.0.0 255.255.255.0" >> /etc/openvpn/server/server.conf
    echo "ifconfig-pool-persist /var/log/openvpn/ipp.txt" >> /etc/openvpn/server/server.conf
    echo "push \"redirect-gateway def1 bypass-dhcp\"" >> /etc/openvpn/server/server.conf
    echo "push \"dhcp-option DNS 208.67.222.222\"" >> /etc/openvpn/server/server.conf
    echo "client-to-client" >> /etc/openvpn/server/server.conf
    echo "duplicate-cn" >> /etc/openvpn/server/server.conf
    echo "keepalive 10 120" >> /etc/openvpn/server/server.conf
    echo "compress lz4-v2" >> /etc/openvpn/server/server.conf
    echo "max-clients 10" >>/etc/openvpn/server/server.conf
    echo "# user nobody" >> /etc/openvpn/server/server.conf
    echo "# group nobody" >> /etc/openvpn/server/server.conf
    echo "persist-key" >> /etc/openvpn/server/server.conf
    echo "persist-tun" >> /etc/openvpn/server/server.conf
    echo "status /var/log/openvpn/openvpn-status.log" >> /etc/openvpn/server/server.conf
    echo "verb 3" >> /etc/openvpn/server/server.conf
    echo "mute 20" >> /etc/openvpn/server/server.conf
    echo "# explicit-exit-notify 1" >>/etc/openvpn/server/server.conf
    echo "openVPN server configuration finished"
    if prompt-yesno "would you like to start the openvpn server after boot" "yes"; then
      systemctl enable openvpn-server@server
    else
      echo "You need to manually start your openvpn server by typing systemctl start openvpn-server@server"
    fi
  else
    echo "you'll configure stunnel4 and openvpn client mode now"
    echo "Scripts will remove stunnel and openvpn config file first. You can cancel it by typing ctrl+c If you dont want to proceed." 
    rm -rf /etc/stunnel/stunnel.conf
    rm -rf /etc/openvpn/server/server.conf
    echo "configuring stunnel.conf"
    echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
    echo "client=yes" >> /etc/stunnel/stunnel.conf
    echo "accept = 127.0.0.1:11000" >> /etc/stunnel/stunnel.conf
    SERVER_URL=$(prompt "Please input the openvpn server IP:" "")
    echo "connect = ${SERVER_URL}:8443" >> /etc/stunnel/stunnel.conf
    echo "configuring openvpn client"
    echo -n "" > /etc/openvpn/client/client.conf
    echo "client" >> /etc/openvpn/client/client.conf
    echo "proto tcp" >> /etc/openvpn/client/client.conf
    echo "dev tap" >> /etc/openvpn/client/client.conf
    echo "ca /etc/openvpn/easyrsa/pki/ca.crt" >> /etc/openvpn/client/client.conf
    echo "cert /etc/openvpn/easyrsa/pki/issued/client.crt" >> /etc/openvpn/client/client.conf
    echo "key /etc/openvpn/easyrsa/pki/private/client.key" >> /etc/openvpn/client/client.conf
    echo "remote 127.0.0.1 11000" >> /etc/openvpn/client/client.conf
    echo "resolv-retry infinite" >> /etc/openvpn/client/client.conf
    echo "nobind" >> /etc/openvpn/client/client.conf
    echo "compress lz4-v2" >> /etc/openvpn/client/client.conf
    echo "# user nobody" >> /etc/openvpn/client/client.conf
    echo "# group nobody" >> /etc/openvpn/client/client.conf
    echo "persist-key" >> /etc/openvpn/client/client.conf
    echo "persist-tun" >> /etc/openvpn/client/client.conf
    echo "mute 20" >> /etc/openvpn/client/client.conf
    echo "prepare scripts to auto setup routes that need to go via local gateway"
    rm -rf /etc/openvpn/client/nonvpn-routes.up
    rm -rf /etc/openvpn/client/nonvpn-routes.down
    echo "script-security 2" >> /etc/openvpn/client/client.conf
    echo "up /etc/openvpn/client/nonvpn-routes.up" >> /etc/openvpn/client/client.conf
    echo "down /etc/openvpn/client/nonvpn-routes.down" >> /etc/openvpn/client/client.conf
    echo -n "" > /etc/openvpn/client/nonvpn-routes.up
    echo "#!/bin/bash" >> /etc/openvpn/client/nonvpn-routes.up
    echo "echo \"set routes for china IP and VPNserver go via local gateway\"" >> /etc/openvpn/client/nonvpn-routes.up
    echo "LocalGW=\$(route -n | grep eth0 | grep \"0.0.0.0         UG\" | awk '{print \$2}')" >> /etc/openvpn/client/nonvpn-routes.up
    echo "if [ -z \$LocalGW ]; then" >> /etc/openvpn/client/nonvpn-routes.up
    echo "  LocalGW=\$(route -n | grep enp0s25 | grep \"0.0.0.0         UG\" | awk '{print \$2}')" >> /etc/openvpn/client/nonvpn-routes.up
    echo "fi" >> /etc/openvpn/client/nonvpn-routes.up
    echo "if [ -z \$LocalGW ]; then" >> /etc/openvpn/client/nonvpn-routes.up
    echo "   echo \"you need to manually create route to vpn server via local gateway\n\"" >> /etc/openvpn/client/nonvpn-routes.up
    echo "   echo \"comment out nonvpn-routes scripts in config file and try run: route add host <server-ip> gw <gateway> after tunnel set up\"" >> /etc/openvpn/client/nonvpn-routes.up
    echo "else" >> /etc/openvpn/client/nonvpn-routes.up
    echo "  sleep 5"  >>  /etc/openvpn/client/nonvpn-routes.up
    echo "  route add -net 114.114.114.0 netmask 255.255.255.0 gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.up
    echo "  route add -net 101.231.59.0 netmask 255.255.255.0 gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.up
    echo "  route add -net 104.193.88.0 netmask 255.255.255.0 gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.up
    echo "  route add -host ${SERVER_URL} gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.up
    echo "fi" >> /etc/openvpn/client/nonvpn-routes.up
    echo -n "" > /etc/openvpn/client/nonvpn-routes.down
    echo "#!/bin/bash" >> /etc/openvpn/client/nonvpn-routes.down
    echo "echo \"delete routes for china IP and VPNserver go via local gateway\"" >> /etc/openvpn/client/nonvpn-routes.down
    echo "LocalGW=\$(route -n | grep eth0 | grep \"0.0.0.0         UG\" | awk '{print \$2}')" >> /etc/openvpn/client/nonvpn-routes.down
    echo "if [ -z \$LocalGW ]; then" >> /etc/openvpn/client/nonvpn-routes.down
    echo "  LocalGW=\$(route -n | grep enp0s25 | grep \"0.0.0.0         UG\" | awk '{print \$2}')" >> /etc/openvpn/client/nonvpn-routes.down
    echo "fi" >> /etc/openvpn/client/nonvpn-routes.down
    echo "if [ -z \$LocalGW ]; then" >> /etc/openvpn/client/nonvpn-routes.down
    echo "   echo \"you need to manually delete route to vpn server via local gateway\n\"" >> /etc/openvpn/client/nonvpn-routes.down
    echo "   echo \"try run: route del host <server-ip> gw <gateway>\"" >> /etc/openvpn/client/nonvpn-routes.down
    echo "else" >> /etc/openvpn/client/nonvpn-routes.down
    echo "  sleep 3"  >>  /etc/openvpn/client/nonvpn-routes.down
    echo "  route del -net 114.114.114.0 netmask 255.255.255.0 gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.down
    echo "  route del -net 101.231.59.0 netmask 255.255.255.0 gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.down
    echo "  route del -net 104.193.88.0 netmask 255.255.255.0 gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.down
    echo "  route del -host ${SERVER_URL} gw \$LocalGW" >> /etc/openvpn/client/nonvpn-routes.down
    echo "fi" >> /etc/openvpn/client/nonvpn-routes.down 
    echo "chmod a+x /etc/openvpn/client/nonvpn-routes.*"
    chmod a+x /etc/openvpn/client/nonvpn-routes.*
    if prompt-yesno "would you like to auto start openvpn client service" "no" ; then
      systemctl enable openvpn-client@client
      echo "You've enable openvpn client service after boot.with the default configured feature,all trafic will go via vpn server"
      echo "Please manually start openvpn client service by typing: systemctl start openvpn-client@client"
    else
      systemctl disable openvpn-client@client
      echo "Please manually start openvpn client service by typing: systemctl start openvpn-client@client"
      echo "when you start the VPN service, all trafic will go via vpn server as default route"
    fi 
    echo "please put your ca/client certs into the right place of easyrsa/pki before you can use the openvpn client service"
    echo "If you download clientcerts.zip from server, just run: unzip clientcerts.zip -d /etc/openvpn/easyrsa"
    echo "You can use systemctl enable/disable openvpn-client@client to add it into system service and auto run after next boot"
  fi
}


dualvpn_install() {
  echo "about to install both strongswan and openvpn"
  echo "apt install -y strongswan" | tee -a /var/log/pvpn_install.log
  apt install -y strongswan 
  openvpn_install
  if ["dualvpn" = $VPN_TYPE] ; then
    echo "apt install -y strongswan-pki" | tee -a /var/log/pvpn_install.log
    apt install -y strongswan-pki
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
