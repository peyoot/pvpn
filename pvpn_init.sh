#! /bin/bash

# This script install and configure palfort vpn  on your Linux
# machine. You can run the latest installer directly from the web by doing:
#
#     curl https://install.palfort.net | bash

if test -z "$BASH_VERSION"; then
  echo "Please run this script using bash, not sh or any other shell." >&2
  exit 1
fi

# We wrap the entire script in a big function which we only call at the very end, in order to
# protect against the possibility of the connection dying mid-script. This protects us against
# the problem described in this blog post:
#   http://blog.existentialize.com/dont-pipe-to-your-shell.html
_() {

set -euo pipefail

# Declare an array so that we can capture the original arguments.
declare -a ORIGINAL_ARGS

# Allow the environment to override curl's User-Agent parameter. We
# use this to distinguish probably-actual-users installing Palfort VPN
# from the automated test suite, which invokes the install script with
# this environment variable set.
CURL_USER_AGENT="${CURL_USER_AGENT:-palfort-vpn-install-script}"

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
  if [ "${REPORT:-yes}" = "yes" ] ; then
    if USE_DEFAULTS=no prompt-yesno "Hmm, installation failed. Would it be OK to send an anonymous error report to Palfort team so we know something is wrong?
It would only contain this error code: $error_code" "yes" ; then
      echo "Sending problem report..." >&2
      local BEARER_TOKEN="ZiV1jbwHBPfpIjF3LNFv9-glp53F7KcsvVvljgKxQAL"
      local API_ENDPOINT="https://api.palfort.net/api"
      local HTTP_STATUS=$(
        dotdotdot_curl \
          --silent \
          --max-time 20 \
          --data-binary "{\"error_code\":\"$error_code\",\"user-agent\":\"$CURL_USER_AGENT\"}" \
          -H "Authorization: Bearer $BEARER_TOKEN" \
          -X POST \
          --output "/dev/null" \
          -w '%{http_code}' \
          "$API_ENDPOINT")
      if [ "200" == "$HTTP_STATUS" ] ; then
        echo "... problem reported successfully. Your installation did not succeed." >&2
      elif [ "000" == "$HTTP_STATUS" ] ; then
        error "Submitting error report failed. Maybe there is a connectivity problem."
      else
        error "Submitting error report resulted in strange HTTP status: $HTTP_STATUS"
      fi
    else
      echo "Not sending report." >&2
    fi
    echo ""
  fi
  echo "You can report bugs at: http://github.com/peyoot/pvpn" >&2
  exit 1
}

retryable_curl() {
  # This function calls curl to download a file. If the file download fails, it asks the user if it
  # is OK to retry.
  local CURL_FAILED="no"
  curl -A "${CURL_USER_AGENT}" -f "$1" > "$2" || CURL_FAILED="yes"
  if [ "yes" = "${CURL_FAILED}" ] ; then
    if prompt-yesno "Downloading $1 failed. OK to retry?" "yes" ; then
      echo "" >&2
      echo "Download failed. Waiting one second before retrying..." >&2
      sleep 1
      retryable_curl "$1" "$2"
    fi
  fi
}

dotdotdot_curl() {
  # This function calls curl, but first prints "..." to the screen, in
  # an attempt to indicate to the user that the script is waiting on
  # something.
  #
  # It then moves the cursor to the start of the line, so that future
  # echo-ing will overwrite those dots.
  #
  # Since the script is -e, and in general we don't have a reliable
  # thing that we do in the case that curl exits with a non-zero
  # status code, we don't capture the status code; we allow the script
  # to abort if curl exits with a non-zero status.

  # Functions calling dotdotdot_curl expect to capture curl's own
  # stdout. Therefore we do our echo-ing to stderr.

  echo -n '...' >&2

  curl "$@"

  echo -ne '\r' >&2
}

is_port_bound() {
  local SCAN_HOST="$1"
  local SCAN_PORT="$2"

  if [ "${DEV_TCP_USABLE}" = "unchecked" ] ; then
    REPORT=no fail "E_DEV_TCP_UNCHECKED" "Programmer error. The author of install.sh used an uninitialized variable."
  fi

  # We also use timeout(1) from coreutils to avoid this process taking a very long
  # time in the case of e.g. weird network rules or something.
  if [ "${DEV_TCP_USABLE}" = "yes" ] ; then
    if timeout 1 bash -c ": < /dev/tcp/${SCAN_HOST}/${SCAN_PORT}" 2>/dev/null; then
      return 0
    else
      return 1
    fi
  fi

  # If we are using a traditional netcat, then -z (zero i/o mode)
  # works for scanning-type uses. (Debian defaults to this.)
  #
  # If we are using the netcat from the nmap package, then we can use
  # --recv-only --send-only to get the same behavior. (Fedora defaults
  # to this.)
  #
  # nc will either:
  #
  # - return true (exit 0) if it connected to the port, or
  #
  # - return false (exit 1) if it failed to connect to the port, or
  #
  # - return false (exit 1) if we are passing it the wrong flags.
  #
  # So if either if these invocations returns true, then we know the
  # port is bound.
  local DEBIAN_STYLE_INDICATED_BOUND="no"
  ${NC_PATH} -z "$SCAN_HOST" "$SCAN_PORT" >/dev/null 2>/dev/null && DEBIAN_STYLE_INDICATED_BOUND=yes

  if [ "$DEBIAN_STYLE_INDICATED_BOUND" == "yes" ] ; then
      return 0
  fi

  # Not sure yet. Let's try the nmap-style way.
  local NMAP_STYLE_INDICATED_BOUND="no"
  ${NC_PATH} --wait 1 --recv-only --send-only "$SCAN_HOST" "$SCAN_PORT" >/dev/null 2>/dev/null && \
      NMAP_STYLE_INDICATED_BOUND=yes

  if [ "$NMAP_STYLE_INDICATED_BOUND" == "yes" ] ; then
      return 0
  fi

  # As far as we can tell, nmap can't connect to the port, so return 1
  # to indicate it is not bound.
  return 1
}

# writeConfig takes a list of shell variable names and saves them, and
# their contents, to stdout. Therefore, the caller should redirect its
# output to a config file.
writeConfig() {
  while [ $# -gt 0 ]; do
    eval echo "$1=\$$1"
    shift
  done
}

prompt() {
  local VALUE

  # Hack: We read from FD 3 because when reading the script from a pipe, FD 0 is the script, not
  #   the terminal. We checked above that FD 1 (stdout) is in fact a terminal and then dup it to
  #   FD 3, thus we can input from FD 3 here.
  if [ "yes" = "$USE_DEFAULTS" ] ; then
    # Print the default.
    echo "$2"
    return
  fi

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

# Define global variables that the install script will use to mark its
# own progress.

DEFAULT_VPN_SERVER="notavailable"
VPNCLIENT="yes"

USE_DEFAULTS="no"
USE_EXTERNAL_INTERFACE="no"
CURRENTLY_UID_ZERO="no"
PREFER_ROOT="yes"
SHOW_MESSAGE_ABOUT_NEEDING_PORTS_OPEN="no"
STARTED_SANDSTORM="no"

# Allow the test suite to override the path to netcat in order to
# reproduce a compatibility issue between different nc versions.
NC_PATH="${OVERRIDE_NC_PATH:-nc}"

# Allow install.sh to store if bash /dev/tcp works.
DEV_TCP_USABLE="unchecked"

# Defaults for some config options, so that if the user requests no
# prompting, they get these values.
DEFAULT_DIR_FOR_ROOT="${OVERRIDE_SANDSTORM_DEFAULT_DIR:-/opt/sandstorm}"
DEFAULT_DIR_FOR_NON_ROOT="${OVERRIDE_SANDSTORM_DEFAULT_DIR:-${HOME:-opt}/sandstorm}"
DEFAULT_SMTP_PORT="30025"
DEFAULT_UPDATE_CHANNEL="dev"
DEFAULT_SERVER_USER="${OVERRIDE_SANDSTORM_DEFAULT_SERVER_USER:-sandstorm}"
SANDCATS_BASE_DOMAIN="${OVERRIDE_SANDCATS_BASE_DOMAIN:-sandcats.io}"
ALLOW_DEV_ACCOUNTS="false"
SANDCATS_GETCERTIFICATE="${OVERRIDE_SANDCATS_GETCERTIFICATE:-yes}"

# Define functions for each stage of the install process.

usage() {
  echo "usage: $SCRIPT_NAME [-d] [-e] [-p PORT_NUMBER] [-u] [<bundle>]" >&2
  echo "If <bundle> is provided, it must be the name of a Sandstorm bundle file," >&2
  echo "like 'sandstorm-123.tar.xz', which will be installed. Otherwise, the script" >&2
  echo "downloads a bundle from the internet via HTTP." >&2
  echo '' >&2
  echo 'If -d is specified, the auto-installs with defaults suitable for app development.' >&2
  echo 'If -e is specified, default to listening on an external interface, not merely loopback.' >&2
  echo 'If -i is specified, default to (i)nsecure mode where we do not request a HTTPS certificate.' >&2
  echo 'If -p is specified, use its argument (PORT_NUMBER) as the default port for HTTP. Otherwise, use 6080. Note that if the install script enables HTTPS via sandcats.io, it will use 443 instead!'
  echo 'If -u is specified, default to avoiding root priviliges. Note that the dev tools only work if the server as root privileges.' >&2
  exit 1
}

detect_current_uid() {
  if [ $(id -u) = 0 ]; then
    CURRENTLY_UID_ZERO="yes"
  fi
}

disable_smtp_port_25_if_port_unavailable() {
  PORT_25_AVAILABLE="no"
  if is_port_bound 0.0.0.0 25; then
    return
  fi
  if is_port_bound 127.0.0.1 25; then
    return
  fi
  PORT_25_AVAILABLE="yes"
}

disable_https_if_ports_unavailable() {
  # If port 80 and 443 are both available, then let's use DEFAULT_PORT=80. This value is what the
  # Sandstorm installer will write to PORT= in the Sandstorm configuration file.
  #
  # If either 80 or 443 is not available, then we set SANDCATS_GETCERTIFICATE to no.
  #
  # From the rest of the installer's perspective, if SANDCATS_GETCERTIFICATE is yes, it is safe to
  # bind to port 443.
  #
  # There is a theoretical race condition here. I think that's life.
  #
  # This also means that if a user has port 443 taken but port 80 available, we will use port 6080
  # as the default port. If the user wants to override that, they can run install.sh with "-p 80".
  local PORT_80_AVAILABLE="no"
  is_port_bound 0.0.0.0 80 || PORT_80_AVAILABLE="yes"

  local PORT_443_AVAILABLE="no"
  is_port_bound 0.0.0.0 443 || PORT_443_AVAILABLE="yes"

  if [ "$PORT_443_AVAILABLE" == "no" -o "$PORT_80_AVAILABLE" == "no" ] ; then
    SANDCATS_GETCERTIFICATE="no"
    SHOW_MESSAGE_ABOUT_NEEDING_PORTS_OPEN="yes"
  fi
}


handle_args() {
  SCRIPT_NAME=$1
  shift

  while getopts "c:deiup:t:m:" opt; do
    case $opt in
      d)
        USE_DEFAULTS="yes"
        ;;
      c)
        VPNCLIENT="yes"
        ;;
      u)
        PREFER_ROOT=no
        ;;
      p)
        DEFAULT_PORT="${OPTARG}"
        ;;
      t)
	VPN_TYPE="${OPTARG}"
	if [ "openvpn" = "${VPN_TYPE}" ] || [ "${VPN_TYPE}" = "strongswan" ] ; then
              echo "you'll install and set up ${VPN_TYPE}"
        else
	  echo  "wrong vpn type"
          return 1
        fi
	;;
      m)
        VPN_MODE="${OPTARG}"
	if [ "$VPN_MODE" = "server" ] ; then
		VPNCLIENT="no"
        elif [ "$VPN_MODE" = "client" ] ; then
		VPNCLIENT="yes"
        else 
	  echo  "wrong vpn mode"
          return 1
        fi
        ;;
	*)
        usage
        ;;
    esac
  done

  # if VPN_TYPE and VPN_MODE didn't get set above, set it to openvpn and client here
  VPN_TYPE="${VPN_TYPE:-openvpn}"
  VPN_MODE="${VPN_MODE:-client}"
  
  # If DEFAULT_PORT didn't get set above, set it to 6080 here.
  DEFAULT_PORT="${DEFAULT_PORT:-6080}"

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

rerun_script_as_root() {
  # Note: This function assumes that the caller has requested
  # permission to use sudo!

  # Pass $@ here to enable the caller to provide environment
  # variables to bash, which will affect the execution plan of
  # the resulting install script run.

  # Remove newlines in $@, otherwise when we try to use $@ in a string passed
  # to 'bash -c' the command gets cut off at the newline. ($@ contains newlines
  # because at the call site we used escaped newlines for readability.)
  local ENVVARS=$(echo $@)

  # Add CURL_USER_AGENT to ENVVARS, since we always need to pass this
  # through.
  ENVVARS="$ENVVARS CURL_USER_AGENT=$CURL_USER_AGENT"

  if [ "$(basename $SCRIPT_NAME)" == bash ]; then
    # Probably ran like "curl https://palfort.net/install.sh | bash"
    echo "Re-running script as root..."

    exec sudo bash -euo pipefail -c "curl -fs -A $CURL_USER_AGENT https://install.palfort.net | $ENVVARS bash"
  elif [ "$(basename $SCRIPT_NAME)" == install.sh ] && [ -e "$0" ]; then
    # Probably ran like "bash install.sh" or "./install.sh".
    echo "Re-running script as root..."
    if [ ${#ORIGINAL_ARGS[@]} = 0 ]; then
      exec sudo $ENVVARS bash "$SCRIPT_NAME"
    else
      exec sudo $ENVVARS bash "$SCRIPT_NAME" "${ORIGINAL_ARGS[@]}"
    fi
  fi

  # Don't know how to run the script. Let the user figure it out.
  REPORT=no fail "E_CANT_SWITCH_TO_ROOT" "ERROR: This script could not detect its own filename, so could not switch to root. \
Please download a copy and name it 'install.sh' and run that as root, perhaps using sudo. \
Try this command:

curl https://install.palfort.net/ > install.sh && sudo bash install.sh"
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

assert_linux_x86_64() {
  if [ "$(uname)" != Linux ]; then
    fail "E_NON_LINUX" "Sandstorm requires Linux. If you want to run Sandstorm on a Windows or
Mac system, you can use Vagrant or another virtualization tool. See our install documentation:

- https://docs.sandstorm.io/en/latest/install/"
  fi

  if [ "$(uname -m)" != x86_64 ]; then
    fail "E_NON_X86_64" "Sorry, the Sandstorm server currently only runs on x86_64 machines."
  fi
}

assert_usable_kernel() {
  KVERSION=( $(uname -r | grep -o '^[0-9.]*' | tr . ' ') )

  if (( KVERSION[0] < 3 || (KVERSION[0] == 3 && KVERSION[1] < 10) )); then
    error "Detected Linux kernel version: $(uname -r)"
    fail "E_KERNEL_OLDER_THAN_310" "Sorry, your kernel is too old to run Sandstorm. We require kernel" \
         "version 3.10 or newer."
  fi
}

maybe_enable_userns_sysctl() {
  # This function enables the Debian/Ubuntu-specific unprivileged
  # userns sysctl, if the system has it and we want it.

  if [ "$USE_DEFAULTS" != "yes" ] ; then
    # Only do this when -d is passed. -d means "use defaults suitable for app development", and
    # we want userns enabled for app development if possible since it enables UID randomization
    # which helps catch app bugs. For the rest of the world, we're fine using the privileged
    # sandbox instead.
    return
  fi

  if [ "no" = "$CURRENTLY_UID_ZERO" ] ; then
    # Not root. Can't do anything about it.
    return
  fi

  if [ ! -e /proc/sys/kernel/unprivileged_userns_clone ]; then
    # No such sysctl on this system.
    return
  fi

  local OLD_VALUE="$(< /proc/sys/kernel/unprivileged_userns_clone)"

  if [ "$OLD_VALUE" = "1" ]; then
    # Already enabled.
    return
  fi

  # Enable it.
  if sysctl -wq kernel.unprivileged_userns_clone=1 2>/dev/null; then
    echo "NOTE: Enabled unprivileged user namespaces because you passed -d."
  else
    # Apparently we can't. Maybe we're in a Docker container. Give up and use privileged sandbox.
    return
  fi

  # Also make sure it is re-enabled on boot. If sysctl.d exists, we drop our own config in there.
  # Otherwise we edit sysctl.conf, but that's less polite.
  local SYSCTL_FILENAME="/etc/sysctl.conf"
  if [ -d /etc/sysctl.d ] ; then
    SYSCTL_FILENAME="/etc/sysctl.d/50-sandstorm.conf"
  fi

  if ! cat >> "$SYSCTL_FILENAME" << __EOF__

# Enable non-root users to create sandboxes (needed by Sandstorm).
kernel.unprivileged_userns_clone = 1
__EOF__
  then
    # We couldn't make the change permanent, so undo the change. Probably everything will work
    # fine with the privileged sandbox. But if it doesn't, it's better that things fail now rather
    # than wait for a reboot.
    echo "NOTE: Never mind, not enabling userns because can't write /etc/sysctl.d."
    sysctl -wq "kernel.unprivileged_userns_clone=$OLD_VALUE" || true
    return
  fi
}

test_if_dev_tcp_works() {
  # In is_port_bound(), we prefer to use bash /dev/tcp to check if the port is bound. This is
  # available on most Linux distributions, but it is a compile-time flag for bash and at least
  # Debian historically disabled it.
  #
  # To test availability, we connect to localhost port 0, which is never available, hoping for a
  # TCP-related error message from bash. We use a subshell here because we don't care that timeout
  # will return false; we care if the grep returns false.
  if (timeout 1 bash -c ': < /dev/tcp/localhost/0' 2>&1 || true) | grep -q 'connect:' ; then
    # Good! bash should get "Connection refused" on this, and this message is prefixed
    # by the syscall it was trying to do, so therefore it tried to connect!
    DEV_TCP_USABLE="yes"
  else
    DEV_TCP_USABLE="no"
  fi
}

assert_dependencies() {
  if [ -z "${BUNDLE_FILE:-}" ]; then
    which curl > /dev/null|| fail "E_CURL_MISSING" "Please install curl(1). Sandstorm uses it to download updates."
  fi

  # To find out if port 80 and 443 are available, we need a working bash /dev/net or `nc` on
  # the path.
  if [ "${DEV_TCP_USABLE}" = "unchecked" ] ; then
    test_if_dev_tcp_works
  fi
  if [ "${DEV_TCP_USABLE}" = "no" ] ; then
    which nc > /dev/null || fail "E_NC_MISSING" "Please install nc(1). (Package may be called 'netcat-traditional' or 'netcat-openbsd'.)"
  fi

  which tar > /dev/null || fail "E_TAR_MISSING" "Please install tar(1)."
  which xz > /dev/null || fail "E_XZ_MISSING" "Please install xz(1). (Package may be called 'xz-utils'.)"
}

assert_valid_bundle_file() {
  # ========================================================================================
  # Validate bundle file, if provided

  if [ -n "${BUNDLE_FILE:-}" ]; then
    # Read the first filename out of the bundle, which should be the root directory name.
    # We use "|| true" here because tar is going to SIGPIPE when `head` exits.
    BUNDLE_DIR=$( (tar Jtf "$BUNDLE_FILE" || true) | head -n 1)
    if [[ ! "$BUNDLE_DIR" =~ sandstorm-([0-9]+)/ ]]; then
      fail "E_INVALID_BUNDLE" "$BUNDLE_FILE: Not a valid Sandstorm bundle"
    fi

    BUILD=${BASH_REMATCH[1]}

    # We're going to change directory, so note the bundle's full name.
    BUNDLE_FILE=$(readlink -f "$BUNDLE_FILE")
  fi
}


########## Function Area#########
check_run_as_root(){
    if [ "no" = "$CURRENTLY_UID_ZERO" ] ; then
      rerun_script_as_root
    else
      echo "already root"
    fi
    

}
confirm_install() {
  #Perform installation status check, if no installation before, ask user to confirm.
  #use /etc/default/pvpn.conf as status file
  PVPN_INSTALLED="no"
  if [ -e /etc/default/pvpn.conf ]; then
    PVPN_INSTALLED="yes"
    echo ""
    echo "It seems you've already installed palfort vpn. Installation aborded..." 
    return
  fi
  echo "you're about to install ${VPN_TYPE} in ${VPN_MODE} mode"
  if [[ "yes"=${VPNCLIENT} && "notavailable"=${DEFAULT_VPN_SERVER} ]] ; then
    PVPN_SERVER=$(prompt "please input VPN's server IP" "$DEFAULT_VPN_SERVER")
    echo ""
    echo "scripts will help you install vpn software and configure it as you specified"
    echo "if you're not ready, please cancel the installation by enter no"
    echo "Type yes to continue" 
    if prompt-yesno "OK to continue?" "yes" ; then
      perform_install
    else
      echo "installation aborded" 
      return
    fi
  fi
}


perform_install() {

  if [ "strongswan" = "${VPN_TYPE}" ] ; then
    strongswan_install
  fi

  if [ "openvpn" = "${VPN_TYPE}" ] ; then
    openvpn_install
  fi

}


openvpn_install () {
  OVPN_INSTALLED="no"
  if [ -e /etc/openvpn ] ; then
    OVPN_INSTALLED="yes"
    echo "" 
    echo "OpenVPN already installed..., scripts will try to reinstall and configure it anyway"
  fi
  echo "You're about to install openvpn and stunnel4"
  apt update
  apt install openvpn stunnel4
  if prompt-yesno "would you like to remove openvpn autorun service" "yes"; then
    update-rc.d -f openvpn remove
  else
    echo "openvpn will automatically run after booting"
  fi
  echo "Now scripts will configure your VPN based on your choice"
  echo "enable stunnel4 autorun after boot"
  sed -i "s/^ENABLED=0/ENABLED=1/" /etc/default/stunnel4
  echo "configuring stunnel4 now"
  if [ "client" = ${VPN_MODE} ] ; then
    #configure stunnel client  here
    echo -n "" > /etc/stunnel/stunnel.conf
    echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
    echo "client=yes" >> /etc/stunnel/stunnel.conf
    echo "accept=127.0.0.1:11000: >> /etc/stunnel/stunnel.conf
    echo "connect=${PVPN_SERVER}:8443 >> /etc/stunnel/stunnel.conf
    #configure openvpn client here
    echo -n "" > /etc/openvpn/client.conf
    echo "client" >> /etc/openvpn/client.conf
    echo "dev tap" >> /etc/openvpn/client.conf
    echo "proto tcp-client" >> /etc/openvpn/client.conf
    echo "remote 127.0.0.1 11000" >> /etc/openvpn/client.conf
    echo "resolv-retry infinite" >> /etc/openvpn/client.conf
    echo "nobind" >> /etc/openvpn/client.conf
    echo "mute-replay-warnings" >> /etc/openvpn/client.conf
    echo "Now scripts will download vpn credentials for you, you'll be asked to input password for downloading from palfort cloud"
    curl -u robin -O https://pan.palfort.com/remote.php/webdav/Documents/palfort/IT/vpn/openvpn/com-povpn-aws-sg.zip --progress
    echo "need to wait some seconds till the keys were fully downloaded"
    sleep 10
    if prompt-yesno "You need to wail till 100% download. Is downloading finished?" "yes" ; then
      unzip -fo -P kissme com-povpn-aws-sg.zip -d /etc/openvpn/
    else
      fail "not able to download keys"
    fi
    rm -rf com-povpn-aws-sg.zip
    echo "ca /etc/openvpn/keys/ca.crt" >> /etc/openvpn/client.conf
    echo "cert /etc/openvpn/keys/com-ovpn-aws-sg.crt" >> /etc/openvpn/client.conf
    echo "key /etc/openvpn/keys/com-ovpn-asw-sg.key" >> /etc/openvpn/client.conf
    echo "script-security 2 system" >> /etc/openvpn/client.conf
    echo "up /etc/openvpn/nonvpn-route.up" >> /etc/openvpn/client.conf
    echo "down /etc/openvpn/nonvpn-route.down" >> /etc/openvpn/client.conf
    echo "comp-lzo" >> /etc/openvpn/client.conf
    echo "verb 3" >> /etc/openvpn/client.conf
    echo "openvpn client configuration finished!"

  else
    #configure stunnel server here
    echo -n "" > /etc/stunnel/stunnel.conf
#   fetch_server_auth
    echo "cert=/etc/stunnel/stunnel.pem" >> /etc/stunnel/stunnel.conf
    echo "key=/etc/stunnel/stunnel.key" >> /etc/stunnel/stunnel.conf
    echo "[openvpn-localhost]" >> /etc/stunnel/stunnel.conf
    echo "accept =8443" >> /etc/stunnel/stunnel.conf
    echo "connect = 127.0.0.1:11000" >> /etc/stunnel/stunnel.conf
    #configure openvpn server here
    echo -n "" > /etc/openvpn/server.conf
    echo "port 11000" >> /etc/openvpn/server.conf
    echo "proto tcp" >> /etc/openvpn/server.conf
    echo "dev tao" >> /etc/openvpn/server.conf
    echo "ca /etc/easy-rsa/keys/ca.crt" >> /etc/openvpn/server.conf
    echo "cert /etc/easy-rsa/keys/palfort-ovpn-server.crt" >> /etc/openvpn/server.conf
    echo "key /etc/easy-rsa/keys/palfort-ovpn-server.key" >> /etc/openvpn/server.conf
    echo "dh /etc/easy-rsa/keys/dh1024.pem" >> /etc/openvpn/server.conf
    echo "" >> /etc/openvpn/server.conf
    echo "server 10.8.0.0 255.255.255.0" >> /etc/openvpn/server.conf
    echo "ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server.conf
    echo ";client-config-dir ccd" >> /etc/openvpn/server.conf
    echo "push \"redirect-gateway def bypass-dhcp\"" >> /etc/openvpn/server.conf
    echo "push \"dhcp-option DNS 8.8.8.8\"" >> /etc/openvpn/server.conf
    echo "client-to-client" >> /etc/openvpn/server.conf
    echo "keepalive 10 120" >> /etc/openvpn/server.conf
    echo "comp-lzo" >> /etc/openvpn/server.conf
    echo "max-clients 100" >>/etc/openvpn/server.conf
    echo "user nobody" >> /etc/openvpn/server.conf
    echo "group nobody" >> /etc/openvpn/server.conf
    echo ";persist-key" >> /etc/openvpn/server.conf
    echo ";persist-tun" >> /etc/openvpn/server.conf
    echo "status openvpn-status.log" >> /etc/openvpn/server.conf
    echo "verb 0" >> /etc/openvpn/server.conf
    echo "openVPN server configuration finished"
  fi
   
#to be continued
}


strongswan_install () {
  SSWAN_INSTALLED="no"
  USE_CURRENT_CA="no"
  if [ -e /etc/strongswan.d ]; then
    SSWAN_INSTALLED="yes"
    echo ""    
    echo "Strongswan already instaled...." 
  fi
  if [  "no" = "$SSWAN_INSTALLED" ]; then
    echo "scripts now will install strongswan to the server..."
    sudo apt update
    sudo apt install strongswan 
    echo "..."  
    echo "strongswang have been installed. Scripts will now try to fetch certs and key if needed " 
  fi
  if [ -e /etc/ipsec.d/cacerts/cacert.pem ]; then
    if prompt-yesno "Found CA already there, Do you still want a new CA?" no ; then
      if prompt-yesno "generate brand-new ca key and cert?" "yes" ; then
        echo "you choose to generate new ca key and ca cert"
        DEFAULT_CA_CN=$(prompt "please input the CN for the CA certs, Normaly by default it is vpn.palfort.com" "vpn.palfort.com")
        ipsec pki --gen --outform pem > /etc/ipsec.d/private/cakey.pem
        ipsec pki --self --in /etc/ipsec.d/private/cakey.pem --dn "C=CH,O=Palfort,CN=${DEFAULT_CA_CN}" --ca --outform pem > /etc/ipsec.d/cacerts/cacert.pem
        echo "cakey and cacert have been generated and stored"
      else
        echo "you've choose to download ca key and cert from palfort server. you'll be asked for the credentail while prepare to downloading the ca eky" 
        curl -u robin -O https://pan.palfort.com/remote.php/webdav/Documents/palfort/IT/vpn/strongswan/ca-strongswan-aws-sg.zip
        if prompt-yesno "You need to wail till 100% download. Is downloading finished?" "yes" ; then
          unzip -fo -P kissme ca-strongswan-aws-sg.zip -d /etc/ipsec.d/
          echo "ca key and cert have been extract to the /etc/ipsec.d"
        else
          fail "not able to download keys"
        fi
      fi
    fi
  fi
  echo "you're about to generate your server key with the CA"    
  echo "generate a server key"
  ipsec pki --gen --outform pem > /etc/ipsec.d/private/serverkey.pem
  echo "issue a server cert with ca"
  ipsec pki --pub --in /etc/ipsec.d/private/serverkey.pem | ipsec pki --issue --cacert /etc/ipsec.d/cacerts/cacert.pem --cakey /etc/ipsec.d/private/cakey.pem --dn "C=CH,O=Palfort,CN=${PVPN_SERVER}" --san="${PVPN_SERVER}" --flag serverAuth --flag ikeIntermediate --outform pem > /etc/ipsec.d/certs/servercert.pem
  echo "now server cert have issued"
  echo "keys and certs are ready. Now will configure ipsec.conf and ipsec.secrets"
  echo "you need to generate and manage road worriors' certs case by case."
  configure_ipsec

}



configure_ipsec () {
# backup previous configuration based on date
      DATE=$(date +%Y%m%d)
#      rsync -avzP '-e ssh -p 10022' ${CA_SERVER}:/etc/ipsec.d/cacerts/cacert.pem /etc/ipsec.d/cacerts/
      echo "now backup ipsec.conf and ipsec.secrets to /tmp/..."
      # backup ipsec.conf and ipsec.secrets
      if [ -e /etc/ipsec.conf ] ; then
      cp /etc/ipsec.conf /tmp/ipsec.bk${DATE}.conf
      elif [ -e /etc/ipsec.secrets ] ; then
      cp /etc/ipsec.secrets /tmp/ipsec.bk${DATE}.secrets
      echo "backup done"
      fi

  if [ "server" = "$VPN_MODE" ] ; then
#     configure strongswan as VPN server with public IP
      echo " "
      echo "You have choosed to configure this server as palfort VPN and other clients may connect to this server"
      echo "wring configuration ..."
      echo -n "" > /etc/ipsec.conf
      echo "# ipsec.conf - strongswan ipsec configuration file\n" > /etc/ipsec.conf
      echo "config setup" >> /etc/ipsec.conf
      echo " " >> /etc/ipsec.conf
      echo "conn %default" >> /etc/ipsec.conf
      echo "  keyexchange=ikev2" >> /etc/ipsec.conf
      echo "conn palfortvpn" >> /etc/ipsec.conf
      echo "  left=%defaultroute" >> /etc/ipsec.conf
      echo "  leftcert=servercert.pem" >> /etc/ipsec.conf
      echo "  leftid=${PVPN_SERVER} " >> /etc/ipsec.conf
      echo "  right=%any " >> /etc/ipsec.conf
      echo "  auto=add"  >> /etc/ipsec.conf
      echo -n "" > /etc/ipsec.secrets
      echo ": RSA serverkey.pem" >> /etc/ipsec.secrets
      echo "VPN server configuration done"
  else
#    configure strongswan as VPN clinet that don't need public IP and connect to server
      PVPN_CLIENT_ID=$(prompt "please input your ID. Normally your id is part of your email address\(the part before@\)" "common") 
      echo " "
      echo "You have choosed to configure this computer as palfort VPN client that can connect to Palfort VPN server"
      echo "Wright client configuration ..."
      echo -n "" > /etc/ipsec.conf
      echo "# ipsec.conf -strongswan ipsec configuration file \n" > /etc/ipsec.conf
      echo "config setup" >> /etc/ipsec.conf
      echo " " >> /etc/ipsec.conf
      echo "conn %default" >> /etc/ipsec.conf
      echo "  keyexchange=ikev2" >> /etc/ipsec.conf
      echo "conn palfortvpn" >> /etc/ipsec.conf
      echo "  left=%defaultroute" >> /etc/ipsec.conf
      echo "  leftcert=${PVPN_CLIENT_ID}_cert.pem" >> /etc/ipsec.conf
      echo "  leftid=${PVPN_CLIENT_ID}@palfort.com" >> /etc/ipsec.conf
      echo "  right=${PVPN_SERVER}" >> /etc/ipsec.conf
      echo "  auto=add"  >> /etc/ipsec.conf
      echo -n "" >/etc/ipsec.secrets
      echo ": RSA ${PVPN_CLIENT_ID}_cert.pem" >> /etc/ipsec.secrets
      echo " VPN Client configuration done"

  fi
}

save_config() {
write_Config 
}

########## End of Function ######
# Now that the steps exist as functions, run them in an order that
# would result in a working install.
handle_args "$@"
set_umask
assert_on_terminal
assert_linux_x86_64
assert_usable_kernel
detect_current_uid
assert_dependencies
assert_valid_bundle_file
##### all scripts work start here ####
check_run_as_root
confirm_install

#install_strongswan
#choose_vpn_mode
#configure_ipsec
#####
#wait_for_server_bind_to_its_port
#print_success
}

# Now that we know the whole script has downloaded, run it.
_ "$0" "$@"
