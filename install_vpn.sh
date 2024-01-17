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


#check out dey version
DEY_VERSION="$(cat /etc/build |grep DISTRO_VERSION | awk '{print $3}')"
ARR_N+=("4.0-r4")

if [[ "${ARR_N[@]}" =~ "$DEY_VERSION" ]]; then
  OVPN_CONFIG_SDIR="/etc/openvpn/server"
  OVPN_SSERVICE="openvpn-server@server"
  OVPN_CONFIG_CDIR="/etc/openvpn/client"
  OVPN_CSERVICE="openvpn-client@client"
  OVPN_COMPRESS="compress lz4-v2"
  OVPN_LOG_DIR="/var/log/openvpn"
  DNS_UPDATER="update-systemd-resolved"
else
  echo "pvpn is not supported by this version.  Installation aborted"
  exit 1
fi
echo "Your DEY version is: ${DEY_VERSION}"
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

VPN_MODE="client"
VPN_TYPE="openvpn"

if prompt-yesno "Woud you like to use tap interface in openvpn?" yes; then
  OVPN_INTERFACE="tap"
else
  OVPN_INTERFACE="tun"
fi

}

confirm_install() {
  echo "sctips assume you have installed the necessary packaes: unzip,gawk"
  echo "pvpn in DEY by default only work as vpn client"
  echo "check the availability of zip"
  if [ ! -e /usr/bin/unzip ]; then
     echo "your system doesn't have unzip, please add it into firmware"
     exit 1
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
echo "You can use systemctl enable/disable openvpn-client@client to add it into system service and auto run after next boot"
echo "or you can manually start openvpn by input: openvpn /etc/openvpn/client.conf (Ubuntu 16.04) or openvpn /etc/openvpn/client/client.conf (Ubuntu 18.04)"
}


openvpn_config() {
  echo "you'll configure openvpn client now"
  ovpn_config_file
}


ovpn_config_file() {
  if [ "client" = "$VPN_MODE" ] ; then
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
