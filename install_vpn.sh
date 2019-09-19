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
    echo "VPN server mode was chosen"
    VPN_MODE="server"
  else
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
    echo "ONLY openvpn was chosen"
    VPN_TYPE="openvpn"
  else
    VPN_TYPE="dualvpn"
  fi
fi
}

confirm_install() {
  echo "sctips are about to install software you choose"
  echo "you've chosen $VPN_TYPE"
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
    if prompt-yesno "Palfort administrator can download it automatically. Would you like to download it? if you're not authorized, please type no" "no"; then
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
    sleep 1
    echo "Easyrsa PKI initialed" 
    if [ ! -e /etc/openvpn/easyrsa/vars ] ; then
      exec mv vars.example vars
    fi
    echo "about to build CA"
    ./easyrsa build-ca nopass
    echo "CA has been generated by EASYRSA!"
  else
    echo "Initial ipsec pki and build CA now"
  fi
}



openvpn_config() {
  echo "you'll use openvpn and easyRSA as PKI tool"
  if [ "server" = "$VPN_MODE" ] ; then
    cd /etc/openvpn/easyrsa
    echo "Now in /etc/openvpn/easyrsa"
#    if [ ! -e /etc/openvpn/easyrsa/pki ] ; then
#      echo "no PKI foler found,scripts will help you initial one"
#      InitPKI_buildCA
#    fi
    if  [ -e /etc/openvpn/easyrsa/pki/ca.crt ] ; then
      if prompt-yesno "You've got a CA on PKI. Would you like to use it?" "yes" ; then
        echo "use current CA"
      else
        echo "Re-initial PKI and generat a new CA"
        InitPKI_buildCA
      fi
    else
      InitPKI_buildCA
    fi
    echo "now we have known CA is there, start to configure openvpn and stunnel4 as server mode"

  fi
}


dualvpn_install() {
  echo "about to install both strongswan and openvpn"
  apt update
  apt install -y strongswan 
  openvpn_install
  if ["dualvpn" = $VPN_TYPE] ; then
    apt install -y strongswan-pki
  fi

}

openvpn_install()  {
#for openvpn sole installation, need to  install easyrsa aswell
  if [ -e /etc/openvpn ] ; then
   if prompt-yesno "openvpn already installed,reinstall it anyway?" "yes" ; then
     apt update
     apt install -y openvpn stunnel4
   else
     echo "Keep current openvpn installation"
   fi
  fi
  echo "Check chosen vpn type and then install easyrsa3 if it's openvpn solo installation"
  if [ "openvpn" = "$VPN_TYPE" ] ; then
     echo "you're about to install easyRSA3 as PKI tool"
     if [ -e /etc/openvpn/easyrsa ] ; then
       if prompt-yesno "easyrsa PKI already there, remove it fist and then download a new one?" "yes" ; then
         rm -rf /etc/openvpn/easyrsa*
         rm -rf  /tmp/EasyRSA*
         wget -P /tmp/ https://github.com/OpenVPN/easy-rsa/releases/download/${EASYRSA_VERSION}/EasyRSA-unix-${EASYRSA_VERSION}.tgz
         tar xvf /tmp/EasyRSA-unix-${EASYRSA_VERSION}.tgz -C /etc/openvpn/
         mv /etc/openvpn/EasyRSA-${EASYRSA_VERSION} /etc/openvpn/easyrsa
       else  
         echo "you've chosen to use existing easyrsa as PKI"
       fi
     else
       wget -P /tmp/ https://github.com/OpenVPN/easy-rsa/releases/download/${EASYRSA_VERSION}/EasyRSA-unix-${EASYRSA_VERSION}.tgz
       tar xvf /tmp/EasyRSA-unix-${EASYRSA_VERSION}.tgz -C /etc/openvpn/
       mv /etc/openvpn/EasyRSA-${EASYRSA_VERSION} /etc/openvpn/easyrsa
     fi
  else
    echo "you'll use stongswan PKI in openvpn."
  fi
  
}

#vpn_client_install() {

#    echo "about to install vpn client"
#}

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
