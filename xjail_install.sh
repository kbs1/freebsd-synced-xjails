#!/bin/sh

set -e

# Host system INSTALLATION:
# 1) do not install any additional packages for the system (games, docs, src...)
# 2) do not add any new users

# sh compatible markup
GREEN="[0;32m"
YELLOW="[1;33m"
RED="[0;31m"
RESET="[0m"

WORKDIR=~/.xjails
DIR=`pwd`

echog()
{
	echo "${GREEN}${1}${RESET}"
}

echor()
{
	echo "${RED}${1}${RESET}"
}

# parameters: 1 - jailname
setextraperms()
{
	cat /usr/jails/basejail/.setuid_files /usr/jails/"${1}"/.setuid_files > ~/.setuid_files
	while IFS= read -r FILE; do
		[ -f "${FILE}" ] && chmod u+s "${FILE}"
	done < ~/.setuid_files
	rm ~/.setuid_files

	cat /usr/jails/basejail/.setgid_files /usr/jails/"${1}"/.setgid_files > ~/.setgid_files
	while IFS= read -r FILE; do
		[ -f "${FILE}" ] && chmod g+s "${FILE}"
	done < ~/.setgid_files
	rm ~/.setgid_files
}

# parameters: 1 - jailname
addjailmounts()
{
	JAILNAME="${1}"
	echog "Adding linux compatibility mounts and tmp mount to /etc/fstab.${JAILNAME}..."
	mkdir -p /usr/jails/"${JAILNAME}"/compat/linux/proc
	mkdir -p /usr/jails/"${JAILNAME}"/compat/linux/sys
	mkdir -p /usr/jails/"${JAILNAME}"/tmp
	echo "linproc /usr/jails/${JAILNAME}/compat/linux/proc linprocfs rw 0 0" >> /etc/fstab."${JAILNAME}"
	echo "linsys /usr/jails/${JAILNAME}/compat/linux/sys linsysfs rw 0 0" >> /etc/fstab."${JAILNAME}"
	echo "tmpfs /usr/jails/${JAILNAME}/tmp tmpfs rw,mode=777 0 0" >> /etc/fstab."${JAILNAME}"
}

# parameters: 1 - username, 2 - jailname
configurex()
{
	USERNAME="${1}"
	JAILNAME="${2}"
	echog "Configuring '${JAILNAME}' jail X server..."
	read -p "${YELLOW}WARNING: jail directory '/usr/local/etc/X11/xorg.conf.d' is NOT shared between machines and may be configured independently. Default example configuration for this machine will be written now. Press enter to continue.${RESET} " ANSWER

	mkdir -p /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d

	echo 'Section "Files"' > /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	ModulePath   "/usr/local/lib/xorg/modules"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	FontPath     "/usr/local/share/fonts/misc/"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	FontPath     "/usr/local/share/fonts/TTF/"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	FontPath     "/usr/local/share/fonts/OTF/"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	FontPath     "/usr/local/share/fonts/Type1/"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	FontPath     "/usr/local/share/fonts/100dpi/"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	FontPath     "/usr/local/share/fonts/75dpi/"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo '	FontPath     "/usr/local/share/fonts/dejavu/"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf
	echo 'EndSection' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/00-files.conf

	echo 'Section "Module"' > /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/10-modules.conf
	echo '	Load "freetype"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/10-modules.conf
	echo '	Load "glx"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/10-modules.conf
	echo 'EndSection' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/10-modules.conf

	echo 'Section "InputDevice"' > /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/20-inputdevice.conf
	echo '	Identifier "Mouse0"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/20-inputdevice.conf
	echo '	Driver "mouse"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/20-inputdevice.conf
	echo '	Option "Buttons" "5"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/20-inputdevice.conf
	echo '	Option "ZAxisMapping" "4 5"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/20-inputdevice.conf
	echo 'EndSection' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/20-inputdevice.conf

	echo
	read -p "${YELLOW}Enter kernel module name that should be kldloaded on this host *BEFORE* X is started up in the jail. This ensures X server having required modules once launched from jail. Commonly loaded modules: i915kms, radeon, nv, vboxguest. Leave empty if no kldload should be taking place before X init.${RESET} " DRIVER
	echo
	read -p "${YELLOW}Enter X11 driver name that should be used on this machine. Commonly used drivers are: intel, ati, nv, vboxvideo. Leave empty if no specific Device configuration section should be written.${RESET} " XDRIVER
	echo
	read -p "${YELLOW}Enter X11 input driver name that should be used on this machine. Commonly used drivers are: mouse, vboxmouse. Leave empty if no specific InputDevice configuration section should be written.${RESET} " XINPUTDRIVER

	if [ ! -z "${DRIVER}" ]; then
		echo "${USERNAME} ALL=(ALL) NOPASSWD: /sbin/kldload ${DRIVER}" >> /usr/local/etc/sudoers
	fi

	echo -n "${DRIVER}" > ./driver

	if [ ! -z "${XDRIVER}" ]; then
		echo 'Section "Device"' > /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/30-device.conf
		echo '	Identifier "Card0"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/30-device.conf
		echo "	Driver \"${XDRIVER}\"" >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/30-device.conf
		echo 'EndSection' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/30-device.conf
	fi

	if [ ! -z "${XINPUTDRIVER}" ]; then
		echo 'Section "InputDevice"' > /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/40-inputdevice.conf
		echo '	Identifier "Mouse0"' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/40-inputdevice.conf
		echo "	Driver \"${XINPUTDRIVER}\"" >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/40-inputdevice.conf
		echo 'EndSection' >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xorg.conf.d/40-inputdevice.conf
	fi
}

# parameters: 1 - jailname, 2 - jailip
configureipbinds()
{
	JAILNAME="${1}"
	JAILIP="${2}"

	echog "Configuring sshd and ntpd to listen only on '${JAILNAME}' jail IPv4 address..."
	echo >> /usr/jails/"${JAILNAME}"/etc/ssh/sshd_config
	echo -n "ListenAddress ${JAILIP}" >> /usr/jails/"${JAILNAME}"/etc/ssh/sshd_config

	echo >> /usr/jails/"${JAILNAME}"/etc/ntp.conf
	echo "interface ignore wildcard" >> /usr/jails/"${JAILNAME}"/etc/ntp.conf
	echo >> /usr/jails/"${JAILNAME}"/etc/ntp.conf
	echo -n "interface listen ${JAILIP}" >> /usr/jails/"${JAILNAME}"/etc/ntp.conf

	read -p "${YELLOW}NOTICE: the following jail files are NOT shared between machines as they contain jail specific IP binding data: /etc/ntp.conf, /etc/ssh/sshd_config. Press enter to continue.${RESET} " TEMP
}

if [ ! -d $WORKDIR ]; then
	mkdir -p $WORKDIR
fi
cd "${WORKDIR}"

if [ ! -f ./stage ]; then
	echo -n "1" > ./stage
fi

STAGE=`cat stage`

# stage 1 - update the system and obtain basic setup information
if [ "${STAGE}" == "1" ]; then
	read -p "${YELLOW}This script will patch the FreeBSD kernel to allow running Xorg in a jail. It can also create a desktop jail with LXDE installed, that can be synchronised via unison. Continue? [N]${RESET} " ANSWER
	case "${ANSWER}" in
		[Yy]* ) echo;;
		[Nn]* ) exit;;
		* ) exit;;
	esac

	touch ./jailnames

	read -p "${YELLOW}Enter interface name that should be used for all jails, example: 'em0':${RESET} " IFACE
	echo -n "${IFACE}" > ./hostiface

	echo
	read -p "${YELLOW}Enter IP address that your host system uses. To use DHCP assigned IP, type 'DHCP'. This is necessary to setup some services to listen only on specific addresses. You may pres CTRL-C now and set up your network, as no changes have been made so far. Your IP:${RESET} " HOSTIP

	if [ "${HOSTIP}" == "DHCP" -o "${HOSTIP}" == "dhcp" ]; then
		echo
		read -p "${YELLOW}You entered 'DHCP'. This will cause a custom DHCP hook to be executed each time the host system acquires a lease. The hook will reconfigure necessary host system services to listen only on acquired IP, and also configure each jail's sshd and ntpd services. Jail IP will always be host system IP +n, where n is the jail's sequential number, starting from 1 (not kernel's JID). Press enter to continue.${RESET}" TMP
		cat <<EOD > /etc/dhclient-exit-hooks
			RECONFIGURE="false"
			if [ "\$reason" == "BOUND" -o "\$reason" == "RENEW" -o "\$reason" == "REBIND" -o "\$reason" == "REBOOT" ]; then
				RECONFIGURE="true"
			fi

			if [ "\${RECONFIGURE}" == "true" -a "\${interface}" == "${IFACE}" ]; then
				sed -i '' '\$ d' /etc/ssh/sshd_config
				sed -i '' '\$ d' /etc/ssh/sshd_config

				sed -i '' '\$ d' /etc/ntp.conf
				sed -i '' '\$ d' /etc/ntp.conf

				echo >> /etc/ssh/sshd_config
				echo -n "ListenAddress \${new_ip_address}" >> /etc/ssh/sshd_config

				echo >> /etc/ntp.conf
				echo -n "interface listen \${new_ip_address}" >> /etc/ntp.conf

				service sshd status > /dev/null
				if [ \$? == 0 ]; then
					service sshd restart
				fi

				service ntpd status > /dev/null
				if [ \$? == 0 ]; then
					service ntpd restart
				fi

				cp /etc/resolv.conf /usr/jails/newjail/etc/resolv.conf

				LASTBYTE=\`echo "\${new_ip_address}" | cut -d '.' -f 4\`
				FIRSTBYTES=\`echo "\${new_ip_address}" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+'\`
				SEQ=0
				for JAILNAME in \`cat ${WORKDIR}/jailnames\`; do
					SEQ=\`expr "\${SEQ}" + 1\`
					IPBYTE=\`expr "\${LASTBYTE}" + "\${SEQ}"\`
					JAILIP="\${FIRSTBYTES}"."\${IPBYTE}"

					sed -i '' '\$ d' /usr/jails/"\${JAILNAME}"/etc/ssh/sshd_config
					sed -i '' '\$ d' /usr/jails/"\${JAILNAME}"/etc/ssh/sshd_config

					sed -i '' '\$ d' /usr/jails/"\${JAILNAME}"/etc/ntp.conf
					sed -i '' '\$ d' /usr/jails/"\${JAILNAME}"/etc/ntp.conf

					echo >> /etc/ssh/sshd_config
					echo -n "ListenAddress \${JAILIP}" >> /etc/ssh/sshd_config

					echo >> /etc/ntp.conf
					echo -n "interface listen \${JAILIP}" >> /etc/ntp.conf

					cp /etc/resolv.conf /usr/jails/"\${JAILNAME}"/etc/resolv.conf

					# modify ezjail config for this jail
					sed -i '' "s/export jail_\${JAILNAME}_ip=.*/export jail_\${JAILNAME}_ip="\""\${interface}|\${JAILIP}"\""/" /usr/local/etc/ezjail/"\${JAILNAME}"

					jls | grep -wq "\${JAILNAME}"
					if [ \$? == "0" ]; then
						# jail is running
						# get kernel's jid
						JAILID=\`jls | grep -w "\${JAILNAME}" | awk '{\$1=\$1};1' | cut -d ' ' -f 1\`
						jail -m ip4.addr="\${JAILIP}" jid="\${JAILID}"
						ezjail-admin console -e "/usr/sbin/service sshd restart"
						ezjail-admin console -e "/usr/sbin/service ntpd restart"
					fi
				done
			fi
EOD
		chmod +x /etc/dhclient-exit-hooks
		HOSTIP="DHCP"
	fi

	echo -n "${HOSTIP}" >> ./hostip

	if [ "${HOSTIP}" == "DHCP" ]; then
		CURHOSTIP=`/sbin/ifconfig "${IFACE}" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'`
		if [ $? == "0" ]; then
			CURHOSTIP=`echo "${CURHOSTIP}" | head -n 1`
		else
			echor "Unable to obtain current host IP on interface '${IFACE}'. Host config is DHCP, override in '${WORKDIR}/hostip'".
			exit 1
		fi
	else
		CURHOSTIP="${HOSTIP}"
	fi

	# update the system
	echog "Updating the system..."
	freebsd-update fetch --not-running-from-cron
	set +e
	freebsd-update install
	set -e

	echog "Enabling dbus, devd, hald, ipc.shm_allow_removed and raw jail sockets..."
	echo 'dbus_enable="YES"' >> /etc/rc.conf
	echo 'hald_enable="YES"' >> /etc/rc.conf
	echo 'devd_enable="YES"' >> /etc/rc.conf
	echo "security.jail.allow_raw_sockets=1" >> /etc/sysctl.conf
	echo "kern.ipc.shm_allow_removed=1" >> /etc/sysctl.conf

	echog "Enabling ntpd sync on start..."
	echo 'ntpd_sync_on_start="YES"' >> /etc/rc.conf

	echog "Adding procfs mountpoint..."
	echo "proc /proc procfs rw 0 0" >> /etc/fstab

	echog "Enabling linux compatibility..."
	echo 'linux_enable="YES"' >> /etc/rc.conf

	echog "Enabling fdescfs..."
	echo "fdesc /dev/fd fdescfs rw 0 0" >> /etc/fstab

	echog "Mounting /tmp using tmpfs..."
	echo "tmpfs /tmp tmpfs rw,mode=777 0 0" >> /etc/fstab

	echog "Increasing kernel maxfiles to 25000..."
	echo 'kern.maxfiles="25000"' >> /boot/loader.conf

	echog "Adding ClientAliveInterval and ServerAliveInterval into ssh configs..."
	echo "ClientAliveInterval 20" >> /etc/ssh/sshd_config
	echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config

	echo "ServerAliveInterval 20" >> /etc/ssh/ssh_config
	echo "ServerAliveCountMax 3" >> /etc/ssh/ssh_config

	echog "Generating public / private ssh key pair for root..."
	ssh-keygen

	read -p "${YELLOW}Please add current machine's hostname into you localhost pointing entries in /etc/hosts. Press enter to launch editor.${RESET}" TMP
	$EDITOR /etc/hosts

	echog "Installing ca_root_nss..."
	yes | pkg install ca_root_nss

	echog "Fixing ntpd 'leapfile expired less than X days ago' problem and enabling ntpd leapfile fetching in /etc/defaults/periodic.conf..."
	echo 'ntp_leapfile_sources="https://hpiers.obspm.fr/iers/bul/bulc/ntp/leap-seconds.list https://www.ietf.org/timezones/data/leap-seconds.list"' >> /etc/rc.conf
	sed -i '' "s/daily_ntpd_leapfile_enable=\"NO\"/daily_ntpd_leapfile_enable=\"YES\"/g" /etc/defaults/periodic.conf
	service ntpd onefetch

	echog "Configuring sshd and ntpd to listen only on host's IP address (${CURHOSTIP})..."
	echo >> /etc/ssh/sshd_config
	echo -n "ListenAddress ${CURHOSTIP}" >> /etc/ssh/sshd_config

	echo >> /etc/ntp.conf
	echo "interface ignore wildcard" >> /etc/ntp.conf
	echo >> /etc/ntp.conf
	echo -n "interface listen ${CURHOSTIP}" >> /etc/ntp.conf

	echog "Configuring syslog to operate in safe mode (logging only to hosts's filesystem)..."
	echo 'syslogd_flags="-ss"' >> /etc/rc.conf

	echo -n "2" > ./stage

	read -p "${YELLOW}Press enter to reboot the system. If no updates were installed, press 'c' and enter to continue immediately.${RESET} " ANSWER

	if [ "${ANSWER}" != "c" -a "${ANSWER}" != "C" ]; then
		reboot
	else
		STAGE=2
	fi
fi

# stage 2 - compile new kernel and set system settings
if [ "${STAGE}" == "2" ]; then
	read -p "${YELLOW}Select synchronize UI type. Synchronize UI can be command line based or X server based. If you use a driver that does not support vt switching (for example i915kms), you won't be able to get back to text console after the driver is loaded, and X based sync UI must be used in this case. This installs Xorg server also on host. Type: 'X' for Xorg based synchronize UI, 'C' for console based synchronize UI [C]${RESET} " UISTYLE
	if [ "${UISTYLE}" == "x" -o "${UISTYLE}" == "X" ]; then
		UISTYLE="xorg"
	else
		UISTYLE="console"
	fi

	echo -n "${UISTYLE}" > ./uistyle

	# install necessary host system packages
	echog "Installing necessary host system packages..."
	set +e
	yes | pkg install ezjail
	yes | pkg install wget
	yes | pkg install subversion
	yes | pkg install dbus
	yes | pkg install sudo
	yes | pkg install unison-nox11
	yes | pkg install virtualbox-ose-additions
	if [ "${UISTYLE}" == "xorg" ]; then
		yes | pkg install Xorg
		yes | pkg install numlockx
	fi
	set -e

	echog "Generating DBUS machine UUID..."
	dbus-uuidgen --ensure

	VERSION=`freebsd-version | grep -Eo '^[0-9.]+' | head -n 1`
	echog "Detected system version: ${VERSION}"

	# check out current release src
	echog "Checking out release src..."
	find /usr/src -mindepth 1 -delete
	svn co https://svn.freebsd.org/base/releng/"$VERSION" /usr/src --non-interactive --trust-server-cert-failures=unknown-ca
	REVISION=`LANG=C svn info /usr/src | awk '/^Revision:/ {print $2;}'`

	# download kernel patch
	echog "Downloading kernel XJAILS patch..."
	wget --no-check-certificate https://raw.githubusercontent.com/kbs1/freebsd-synced-xjails/master/freebsd_"${VERSION}"_xjails.patch

	# patch the kernel
	echog "Patching the kernel..."
	patch -d /usr/src < freebsd_"${VERSION}"_xjails.patch

	# create custom kernel config name
	echog "Creating custom kernel config..."
	cp /usr/src/sys/amd64/conf/GENERIC /usr/src/sys/amd64/conf/XJAILS_"${VERSION}"_r"${REVISION}"
	cp /usr/src/sys/amd64/conf/GENERIC.hints /usr/src/sys/amd64/conf/XJAILS_"${VERSION}"_r"${REVISION}".hints

	# compile and install new kernel
	echog "Compiling the kernel..."
	cd /usr/src
	make buildkernel KERNCONF=XJAILS_"${VERSION}"_r"${REVISION}"
	echog "Installing the kernel..."
	make installkernel KERNCONF=XJAILS_"${VERSION}"_r"${REVISION}"
	cd "${WORKDIR}"

	read -p "${YELLOW}System will now reboot into the new kernel. Press enter to continue.${RESET} " answer

	echo -n "3" > ./stage
	reboot
fi

# stage 3 - configure X, create devfs rules, install base jail
if [ "${STAGE}" == "3" ]; then
	uname -a | grep XJAILS > /dev/null

	if [ ! $? ]; then
		echor "Not booted into XJAILS kernel. Please boot the appropriate kernel manually. "
		exit 1
	fi

	echog "Configuring devfs rules..."

	cat <<EOD > /etc/devfs.rules
[devfsrules_xjails=8]
add include \$devfsrules_hide_all
add include \$devfsrules_unhide_basic
add include \$devfsrules_unhide_login
add path agpgart unhide
add path console unhide
add path consolectl unhide
add path dri unhide
add path 'dri/*' unhide
add path io unhide
add path 'nvidia*' unhide
add path 'vbox*' unhide
add path sysmouse unhide
add path mem unhide
add path pci unhide
add path tty unhide
add path ttyv0 unhide
add path ttyv1 unhide
add path ttyv8 unhide
add path 'mixer*' unhide
add path 'dsp*' unhide
add path 'cd*' unhide

[system=10]
add path 'usb/*' mode 0660 group operator
EOD

	# install base jail
	echog "Installing base jail..."
	ezjail-admin install

	echog "Configuring base jail..."
	cp /etc/resolv.conf /usr/jails/newjail/etc/
	cp /etc/localtime /usr/jails/newjail/etc/

	read -p "${YELLOW}Configuring basejail unison synchronisation. Please input SSH connection string for storage server root account. Storage server must be accessed as root to synchronize properly. Storage server must use a case-sensitive file system. Example: root@192.168.0.123${RESET} " SSH
	read -p "${YELLOW}Enter SSH connection arguments, if any, for example '-p 1234':${RESET} " SSHARGS
	read -p "${YELLOW}Enter full path where basejail should be synchronised. Example: /unison/basejail${RESET} " BASEROOT

	echog "Creating directory structure on storage server..."
	ssh "${SSH}" $SSHARGS "mkdir -p ${BASEROOT}"

	echo "${SSH}" > basejail_ssh
	echo "${SSHARGS}" > basejail_sshargs
	echo "${BASEROOT}" > basejail_root

	echo 'ezjail_enable="YES"' >> /etc/rc.conf

	echo -n "4" > ./stage
fi

# stage 4 - configure & install chosen jail name
read -p "${YELLOW}Creating new Xorg desktop jail. Enter jail name (no spaces or special characters), for example 'desktop':${RESET} " JAILNAME

echo "${JAILNAME}" | grep -E '^[a-z]+$' > /dev/null
if [ -z "${JAILNAME}" -o ! $? ]; then
	echor "Not a valid jail name, exiting."
	exit 1
fi

NUMJAILS=`cat ./jailnames | wc -w | cut -w -f 2`
IFACE=`cat ./hostiface`
HOSTIP=`cat ./hostip`

if [ "${HOSTIP}" != "DHCP" ]; then
	read -p "${YELLOW}Enter IPv4 address the jail should be assigned, example: '192.168.1.250':${RESET} " JAILIP
else
	CURHOSTIP=`/sbin/ifconfig "${IFACE}" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'`
	if [ $? == "0" ]; then
		CURHOSTIP=`echo "${CURHOSTIP}" | head -n 1`
	else
		echor "Unable to obtain current host IP on interface '${IFACE}'. Host config is DHCP, override in '${WORKDIR}/hostip'".
		exit 1
	fi
	LASTBYTE=`echo "${CURHOSTIP}" | cut -d '.' -f 4`
	FIRSTBYTES=`echo "${CURHOSTIP}" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+'`
	IPBYTE=`expr "${LASTBYTE}" + "${NUMJAILS}"`
	JAILIP="${FIRSTBYTES}"."${IPBYTE}"
fi

echo -n "${JAILNAME} " >> ./jailnames

echog "Creating '${JAILNAME}' jail..."
ezjail-admin create "${JAILNAME}" "${IFACE}|${JAILIP}"

echog "Configuring '${JAILNAME}' jail..."
sed -i '' "s/export jail_${JAILNAME}_devfs_ruleset=\"devfsrules_jail\"/export jail_${JAILNAME}_devfs_ruleset=\"8\"/g" /usr/local/etc/ezjail/"${JAILNAME}"
echo "export jail_${JAILNAME}_enforce_statfs=\"1\"" >> /usr/local/etc/ezjail/"${JAILNAME}"
echo "export jail_${JAILNAME}_parameters=\"allow.raw_sockets=1 allow.sysvipc=1 allow.kmem=1 allow.mount=1\"" >> /usr/local/etc/ezjail/"${JAILNAME}"

SSH=`cat basejail_ssh`
SSHARGS=`cat basejail_sshargs`
BASEROOT=`cat basejail_root`
UISTYLE=`cat uistyle`

UNISON_CMD1="sudo unison /usr/jails/basejail 'ssh://${SSH}/${BASEROOT}'\${BATCH_MODE}\${FORCE1} -owner -group -numericids -auto -times -sshargs '${SSHARGS}'"
UNISON_CMD1_SUDO="/usr/local/bin/unison /usr/jails/basejail ssh\://${SSH}/${BASEROOT} -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD1_SUDO_FORCE_LOCAL="/usr/local/bin/unison /usr/jails/basejail ssh\://${SSH}/${BASEROOT} -force /usr/jails/basejail -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD1_SUDO_FORCE_REMOTE="/usr/local/bin/unison /usr/jails/basejail ssh\://${SSH}/${BASEROOT} -force ssh\://${SSH}/${BASEROOT} -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD1_SUDO_BATCH="/usr/local/bin/unison /usr/jails/basejail ssh\://${SSH}/${BASEROOT} -batch -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD1_SUDO_BATCH_FORCE_LOCAL="/usr/local/bin/unison /usr/jails/basejail ssh\://${SSH}/${BASEROOT} -batch -force /usr/jails/basejail -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD1_SUDO_BATCH_FORCE_REMOTE="/usr/local/bin/unison /usr/jails/basejail ssh\://${SSH}/${BASEROOT} -batch -force ssh\://${SSH}/${BASEROOT} -owner -group -numericids -auto -times -sshargs ${SSHARGS}"

read -p "${YELLOW}Configuring '${JAILNAME}' unison synchronisation. Please input SSH connection string for storage server root account. Storage server must be accessed as root to synchronize properly. Storage server must use a case-sensitive file system. Example: root@192.168.0.123${RESET} " SSH
read -p "${YELLOW}Enter SSH connection arguments, if any, for example '-p 1234':${RESET} " SSHARGS
read -p "${YELLOW}Enter full path where '${JAILNAME}' should be synchronised. Example: /unison/${JAILNAME}${RESET} " JAILROOT

echog "Creating directory structure on storage server..."
ssh "${SSH}" ${SSHARGS} "mkdir -p ${JAILROOT}"

read -p "${YELLOW}Creating '${JAILNAME}' jail user login. This host system account will automatically log in as the same user account in jail. Enter login name:${RESET} " USERNAME
read -p "${YELLOW}Enter password:${RESET} " PASSWORD

echo "${USERNAME}::::::${USERNAME}::/bin/sh:${PASSWORD}" | adduser -f -

echog "Adding user '${USERNAME}' to group 'wheel'..."
pw user mod "${USERNAME}" -G wheel

configurex "${USERNAME}" "${JAILNAME}"
DRIVER=`cat driver`

echog "Writing session start and end scripts for user '${USERNAME}'..."
UNISON_CMD2="sudo unison /usr/jails/${JAILNAME} 'ssh://${SSH}/${JAILROOT}'\${BATCH_MODE}\${FORCE2} -ignore 'Path etc/resolv.conf' -ignore 'Path usr/local/etc/X11/xorg.conf.d' -ignore 'Path etc/ssh/sshd_config' -ignore 'Path etc/ntp.conf' -ignore 'Path var/run' -ignore 'Path var/spool' -ignore 'Path tmp' -owner -group -numericids -auto -times -sshargs '${SSHARGS}'"
UNISON_CMD2_SUDO="/usr/local/bin/unison /usr/jails/${JAILNAME} ssh\://${SSH}/${JAILROOT} -ignore Path etc/resolv.conf -ignore Path usr/local/etc/X11/xorg.conf.d -ignore Path etc/ssh/sshd_config -ignore Path etc/ntp.conf -ignore Path var/run -ignore Path var/spool -ignore Path tmp -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD2_SUDO_FORCE_LOCAL="/usr/local/bin/unison /usr/jails/${JAILNAME} ssh\://${SSH}/${JAILROOT} -force /usr/jails/${JAILNAME} -ignore Path etc/resolv.conf -ignore Path usr/local/etc/X11/xorg.conf.d -ignore Path etc/ssh/sshd_config -ignore Path etc/ntp.conf -ignore Path var/run -ignore Path var/spool -ignore Path tmp -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD2_SUDO_FORCE_REMOTE="/usr/local/bin/unison /usr/jails/${JAILNAME} ssh\://${SSH}/${JAILROOT} -force ssh\://${SSH}/${JAILROOT} -ignore Path etc/resolv.conf -ignore Path usr/local/etc/X11/xorg.conf.d -ignore Path etc/ssh/sshd_config -ignore Path etc/ntp.conf -ignore Path var/run -ignore Path var/spool -ignore Path tmp -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD2_SUDO_BATCH="/usr/local/bin/unison /usr/jails/${JAILNAME} ssh\://${SSH}/${JAILROOT} -batch -ignore Path etc/resolv.conf -ignore Path usr/local/etc/X11/xorg.conf.d -ignore Path etc/ssh/sshd_config -ignore Path etc/ntp.conf -ignore Path var/run -ignore Path var/spool -ignore Path tmp -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD2_SUDO_BATCH_FORCE_LOCAL="/usr/local/bin/unison /usr/jails/${JAILNAME} ssh\://${SSH}/${JAILROOT} -batch -force /usr/jails/${JAILNAME} -ignore Path etc/resolv.conf -ignore Path usr/local/etc/X11/xorg.conf.d -ignore Path etc/ssh/sshd_config -ignore Path etc/ntp.conf -ignore Path var/run -ignore Path var/spool -ignore Path tmp -owner -group -numericids -auto -times -sshargs ${SSHARGS}"
UNISON_CMD2_SUDO_BATCH_FORCE_REMOTE="/usr/local/bin/unison /usr/jails/${JAILNAME} ssh\://${SSH}/${JAILROOT} -batch -force ssh\://${SSH}/${JAILROOT} -ignore Path etc/resolv.conf -ignore Path usr/local/etc/X11/xorg.conf.d -ignore Path etc/ssh/sshd_config -ignore Path etc/ntp.conf -ignore Path var/run -ignore Path var/spool -ignore Path tmp -owner -group -numericids -auto -times -sshargs ${SSHARGS}"

# write xjail config script - all configuration in one place (included, no shebang)
cat <<EOD > /home/"${USERNAME}"/xjail_config.sh
JAILNAME="${JAILNAME}"
USERNAME="${USERNAME}"
UISTYLE="${UISTYLE}" # "xorg" or "console"
DRIVER="${DRIVER}" # driver that should be kldloaded before entering the xjail, empty string for none
NUMLOCK="numlock" # set this to 'numlock' to run numlockx after UI startup for UISTYLE "xorg"

SSH="${SSH}"
BASEROOT="${BASEROOT}"
JAILROOT="${JAILROOT}"
EOD

# write master flow script - decides whether to use X sync UI or not (included from .profile, no shebang)
cat <<EOD > /home/"${USERNAME}"/xjail_flow.sh
GREEN="[0;32m"
YELLOW="[1;33m"
RED="[0;31m"
RESET="[0m"

. ~/xjail_config.sh

xorg_ui_before()
{
	xinit -bg black -fg white -maximized -e ~/xjail_before.sh
	echo "startx" >> /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	echo "exit" >> /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	sudo ezjail-admin console -e "/usr/bin/login -f \${USERNAME}" "\${JAILNAME}"
}

xorg_ui_after()
{
	sed -i '' '\$ d' /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	sed -i '' '\$ d' /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	xinit -bg black -fg white -maximized -e ~/xjail_after.sh
}

console_ui_before()
{
	~/xjail_before.sh
	echo "" >> /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	echo "" >> /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	sudo ezjail-admin console -e "/usr/bin/login -f \${USERNAME}" "\${JAILNAME}"
}

console_ui_after()
{
	sed -i '' '\$ d' /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	sed -i '' '\$ d' /usr/jails/\${JAILNAME}/home/\${USERNAME}/.profile
	~/xjail_after.sh
}

if [ -z "\${DRIVER}" ]; then
	DRIVER_LOADED="false";
else
	kldstat | grep "\${DRIVER}".ko > /dev/null

	if [ \$? ]; then
		DRIVER_LOADED="true"
	else
		DRIVER_LOADED="false"
	fi
fi

if [ "\${DRIVER_LOADED}" == "true" -a "\${UISTYLE}" == "xorg" ]; then
	# driver already loaded, and X UI was specified
	xorg_ui_before
	xorg_ui_after
else
	# driver not loaded, or console UI was specified
	if [ "\${DRIVER_LOADED}" == "false" -a ! -z "\${DRIVER}" ]; then
		sudo kldload "\${DRIVER}"
		DRIVER_LOADED="true"
	fi

	if [ "\${UISTYLE}" == "xorg" ]; then
		xorg_ui_before
		xorg_ui_after
	else
		console_ui_before
		console_ui_after
	fi
fi

exit
EOD

# write session before script on host
cat <<EOD > /home/"${USERNAME}"/xjail_before.sh
#!/bin/sh

GREEN="[0;32m"
YELLOW="[1;33m"
RED="[0;31m"
RESET="[0m"

. ~/xjail_config.sh

# turn on numlock if requested (running in X mode)
if [ "\${NUMLOCK}" == "numlock" -a "\${UISTYLE}" == "xorg" ]; then
	numlockx
fi

# always copy fresh /etc/resolv.conf to jail
mkdir -p /usr/jails/\${JAILNAME}/etc
sudo cp /etc/resolv.conf /usr/jails/\${JAILNAME}/etc/resolv.conf

# always create tmp directory
mkdir -p /usr/jails/\${JAILNAME}/tmp

echo
read -p "\${YELLOW}Entering jail '\${JAILNAME}'. Select an option [1]:
	1) Enter jail without syncing
	2) Sync changes with server and enter jail
	3) Sync changes with server (batch mode - no questions) and enter jail
	4) Clone changes from server and enter jail
	5) Clone changes from server (batch mode - no questions) and enter jail
	6) Delete current jail FS on disk, resync from server and enter jail
	7) Drop to shell\${RESET}

Append 'b' to the end of your selection to also sync / clone the basejail!

-->	" ANSWER

BATCH_MODE=""
FORCE1=""
FORCE2=""
SYNC="false"
SYNC_BASEJAIL="false"

case "\${ANSWER}" in
	2* ) echo "\${GREEN}Syncing changes with server (interactive mode)...\${RESET}"
		SYNC="true"
	;;
	3* ) echo "\${GREEN}Syncing changes with server (batch mode)...\${RESET}"
		SYNC="true"
		BATCH_MODE=" -batch"
	;;
	4* ) echo "\${GREEN}Cloning changes from server to local machine (interactive mode)...\${RESET}"
		SYNC="true"
		FORCE1=" -force ssh://\${SSH}/\${BASEROOT}"
		FORCE2=" -force ssh://\${SSH}/\${JAILROOT}"
	;;
	5* ) echo "\${GREEN}Cloning changes from server to local machine (batch mode)...\${RESET}"
		SYNC="true"
		BATCH_MODE=" -batch"
		FORCE1=" -force ssh://\${SSH}/\${BASEROOT}"
		FORCE2=" -force ssh://\${SSH}/\${JAILROOT}"
	;;
	6* )
		read -p "\${RED}DELETE current JAIL FS - are you sure? [N] \${RESET}" DELETE
		if [ "\${DELETE}" == "y" -o "\${DELETE}" == "Y" -o "\${DELETE}" == "yes" -o "\${DELETE}" == "YES" ]; then
			SYNC="true"
			BATCH_MODE=" -batch"
			echo "\${GREEN}Stopping '\${JAILNAME}' jail...\${RESET}"
			sudo ezjail-admin stop "\${JAILNAME}"
			sleep 5
			echo "\${GREEN}Deleting current jail filesystem...\${RESET}"
			sudo chflags -R 0 /usr/jails/basejail
			sudo find /usr/jails/basejail -mindepth 1 -delete
			sudo chflags -R 0 /usr/jails/"\${JAILNAME}"
			sudo find /usr/jails/"\${JAILNAME}" -mindepth 1 -delete
			rm -fr /root/.unison/ar*
			rm -fr /root/.unison/fp*
		else
			read -p "\${GREEN}Aborting. Press return to enter jail.\${RESET}" DELETE
		fi
	;;
	7* ) echo "\${GREEN}Dropping to shell...\${RESET}"
		sh
	;;
esac

case "\${ANSWER}" in
	[234567]b* )
		SYNC_BASEJAIL="true"
	;;
esac

SESSION_ENDING="false"
. ~/xjail_sync.sh
EOD

# write session after script on host
cat <<EOD > /home/"${USERNAME}"/xjail_after.sh
#!/bin/sh

GREEN="[0;32m"
YELLOW="[1;33m"
RED="[0;31m"
RESET="[0m"

. ~/xjail_config.sh

# turn on numlock if requested (running in X mode)
if [ "\${NUMLOCK}" == "numlock" -a "\${UISTYLE}" == "xorg" ]; then
	numlockx
fi

echo
read -p "\${YELLOW}Session in jail '\${JAILNAME}' ended. Select an option [1]:
	1) Log out
	2) Sync changes with server (batch mode) and log out
	3) Sync changes with server (batch mode) and reboot
	4) Sync changes with server (batch mode) and shut down
	5) Clone changes to server (batch mode) and log out
	6) Clone changes to server (batch mode) and reboot
	7) Clone changes to server (batch mode) and shut down
	8) Reboot
	9) Shut down
	0) Drop to shell\${RESET}

Append 'b' to the end of your selection to also sync / clone the basejail!

-->	" ANSWER

BATCH_MODE=""
FORCE1=""
FORCE2=""
SYNC="false"
SYNC_BASEJAIL="false"

case "\${ANSWER}" in
	[234]* ) SYNC="true"
		BATCH_MODE=" -batch"
	;;
	[567]* ) SYNC="true"
		BATCH_MODE=" -batch"
		FORCE1=" -force /usr/jails/basejail"
		FORCE2=" -force /usr/jails/\${JAILNAME}"
	;;
esac

case "\${ANSWER}" in
	[234567]b* )
		SYNC_BASEJAIL="true"
	;;
esac

SESSION_ENDING="true"
. ~/xjail_sync.sh

case "\${ANSWER}" in
	[479]* ) sudo init 0;;
	[368]* ) sudo init 6;;
	[125]* ) exit;;
	0* ) echo "\${GREEN}Dropping to shell...\${RESET}"
		sh
	;;
esac
EOD

# write sync script (included, no shebang)
cat <<EOD > /home/"${USERNAME}"/xjail_sync.sh
if [ "\${SYNC}" == "true" ]; then
	sudo ezjail-admin stop "\${JAILNAME}"
	sleep 5

	if [ "\${SESSION_ENDING}" == "true" ]; then
		echo "\${GREEN}Populating setuid and setgid permission index files...\${RESET}"
		sudo ~/xjail_dumpperms.sh
	fi

	if [ "\${SYNC_BASEJAIL}" == "true" ]; then
		echo
		echo "\${GREEN}Synchronizing basejail...\${RESET}"
		${UNISON_CMD1}
	fi

	echo "\${GREEN}Synchronizing '\${JAILNAME}' jail...\${RESET}"
	${UNISON_CMD2}

	if [ "\${SESSION_ENDING}" == "false" ]; then
		echo "\${GREEN}Synchronising setuid and setgid permissions...\${RESET}"
		sudo ~/xjail_setperms.sh
	fi

	sudo ezjail-admin start "\${JAILNAME}"
fi
EOD

# write dump perms script (run as root)
cat <<EOD > /home/${USERNAME}/xjail_dumpperms.sh
#!/bin/sh

. /home/${USERNAME}/xjail_config.sh

rm /usr/jails/basejail/.setuid_files /usr/jails/basejail/.setgid_files /usr/jails/\${JAILNAME}/.setuid_files /usr/jails/\${JAILNAME}/.setgid_files

find /usr/jails/basejail -perm +4000 > /usr/jails/basejail/.setuid_files
find /usr/jails/basejail -perm +2000 > /usr/jails/basejail/.setgid_files

find /usr/jails/\${JAILNAME} -perm +4000 > /usr/jails/\${JAILNAME}/.setuid_files
find /usr/jails/\${JAILNAME} -perm +2000 > /usr/jails/\${JAILNAME}/.setgid_files

chmod 700 /usr/jails/basejail/.setuid_files /usr/jails/basejail/.setgid_files /usr/jails/\${JAILNAME}/.setuid_files /usr/jails/\${JAILNAME}/.setgid_files
EOD

# write set perms script (run as root)
cat <<EOD > /home/${USERNAME}/xjail_setperms.sh
#!/bin/sh

. /home/${USERNAME}/xjail_config.sh

chflags -R 0 /usr/jails/basejail
chflags -R 0 /usr/jails/"\${JAILNAME}"

cat /usr/jails/basejail/.setuid_files /usr/jails/\${JAILNAME}/.setuid_files > ~/.setuid_files
while IFS= read -r FILE; do
	if [ -f "\${FILE}" ]; then
		RPATH=\`realpath "\${FILE}"\`
		if [ \$? ]; then
			if echo "\${RPATH}" | grep -q '^/usr/jails/'; then
				chmod u+s "\${RPATH}"
			else
				echo "WARN: refusing to chmod path '\${RPATH}'"
			fi
		else
			echo "WARN: realpath for '\${FILE}' failed"
		fi
	fi
done < ~/.setuid_files
rm ~/.setuid_files

cat /usr/jails/basejail/.setgid_files /usr/jails/\${JAILNAME}/.setgid_files > ~/.setgid_files
while IFS= read -r FILE; do
	if [ -f "\${FILE}" ]; then
		RPATH=\`realpath "\${FILE}"\`
		if [ \$? ]; then
			if echo "\${RPATH}" | grep -q '^/usr/jails/'; then
				chmod g+s "\${RPATH}"
			else
				echo "WARN: refusing to chmod path '\${RPATH}'"
			fi
		else
			echo "WARN: realpath for '\${FILE}' failed"
		fi
	fi
done < ~/.setgid_files
rm ~/.setgid_files
EOD

chown "${USERNAME}":"${USERNAME}" /home/"${USERNAME}"/xjail_*.sh
chmod +x /home/"${USERNAME}"/xjail_*.sh

chown root:wheel /home/${USERNAME}/xjail_dumpperms.sh
chown root:wheel /home/${USERNAME}/xjail_setperms.sh
chmod 700 /home/${USERNAME}/xjail_dumpperms.sh
chmod 700 /home/${USERNAME}/xjail_setperms.sh

echog "Altering host .profile script for user '${USERNAME}'..."
echo ". ~/xjail_flow.sh" >> /home/"${USERNAME}"/.profile

echog "Giving host system user '${USERNAME}' necessary sudo privileges..."
echo "${USERNAME} ALL=(ALL) NOPASSWD: /usr/local/bin/ezjail-admin console -e /usr/bin/login -f ${USERNAME} ${JAILNAME}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /usr/local/bin/ezjail-admin stop ${JAILNAME}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /usr/local/bin/ezjail-admin start ${JAILNAME}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /usr/local/bin/ezjail-admin restart ${JAILNAME}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD1_SUDO}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD1_SUDO_FORCE_LOCAL}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD1_SUDO_FORCE_REMOTE}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD1_SUDO_BATCH}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD1_SUDO_BATCH_FORCE_LOCAL}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD1_SUDO_BATCH_FORCE_REMOTE}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD2_SUDO}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD2_SUDO_FORCE_LOCAL}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD2_SUDO_FORCE_REMOTE}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD2_SUDO_BATCH}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD2_SUDO_BATCH_FORCE_LOCAL}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: ${UNISON_CMD2_SUDO_BATCH_FORCE_REMOTE}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /sbin/init 0" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /sbin/init 6" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /bin/chflags -R 0 /usr/jails/basejail" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /usr/bin/find /usr/jails/basejail -mindepth 1 -delete" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /bin/chflags -R 0 /usr/jails/${JAILNAME}" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /usr/bin/find /usr/jails/${JAILNAME} -mindepth 1 -delete" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /home/${USERNAME}/xjail_dumpperms.sh" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /home/${USERNAME}/xjail_setperms.sh" >> /usr/local/etc/sudoers
echo "${USERNAME} ALL=(ALL) NOPASSWD: /bin/cp /etc/resolv.conf /usr/jails/${JAILNAME}/etc/resolv.conf" >> /usr/local/etc/sudoers

echo $YELLOW
read -p "${YELLOW}Populate jail '${JAILNAME}' from remote server? Answering no here creates a new jail and installs XFCE environment into it. [N]${RESET} " ANSWER
echo $RESET

if [ "${ANSWER}" == "y" -o "${ANSWER}" == "Y" -o "${ANSWER}" == "YES" -o "${ANSWER}" == "yes" -o "${ANSWER}" == "Yes" ]; then
	# populate jail from remote server

	chflags -R 0 /usr/jails/basejail
	find /usr/jails/basejail -mindepth 1 -delete
	chflags -R 0 /usr/jails/"${JAILNAME}"
	find /usr/jails/"${JAILNAME}" -mindepth 1 -delete
	BATCH_MODE=" -batch"
	eval "${UNISON_CMD1}"
	eval "${UNISON_CMD2}"

	setextraperms "${JAILNAME}"
	addjailmounts "${JAILNAME}"

	# copy host's sshd_config and ntp.conf over to jail (these files are ignored)
	cp /etc/ssh/sshd_config /usr/jails/"${JAILNAME}"/etc/ssh/sshd_config
	cp /etc/ntp.conf /usr/jails/"${JAILNAME}"/etc/ntp.conf

	# remove last 2 lines from ntp.conf containing binded ip address
	sed -i '' '$ d' /usr/jails/"${JAILNAME}"/etc/ntp.conf
	sed -i '' '$ d' /usr/jails/"${JAILNAME}"/etc/ntp.conf

	# remove last 2 lines from sshd_config containing binded ip address
	sed -i '' '$ d' /usr/jails/"${JAILNAME}"/etc/ssh/sshd_config
	sed -i '' '$ d' /usr/jails/"${JAILNAME}"/etc/ssh/sshd_config

	# write jail specific information into copied config files
	configureipbinds "${JAILNAME}" "${JAILIP}"

	echog "Starting '${JAILNAME}' jail..."
	ezjail-admin start "${JAILNAME}"

else
	# create a new stock jail
	addjailmounts "${JAILNAME}"
	configureipbinds "${JAILNAME}" "${JAILIP}"

	echog "Configuring syslog to operate in safe mode (logging only to jail's filesystem)..."
	echo 'syslogd_flags="-ss"' >> /usr/jails/"${JAILNAME}"/etc/rc.conf

	echog "Starting '${JAILNAME}' jail..."
	ezjail-admin start "${JAILNAME}"

	echog "Copying /etc/passwd, /etc/group and /etc/master.passwd to '${JAILNAME}' jail..."
	cp /etc/passwd /usr/jails/"${JAILNAME}"/etc/passwd
	cp /etc/group /usr/jails/"${JAILNAME}"/etc/group
	cp /etc/master.passwd /usr/jails/"${JAILNAME}"/etc/master.passwd

	echog "Copying user account '${USERNAME}' to '${JAILNAME}' jail..."
	mkdir -p /usr/jails/"${JAILNAME}"/home
	cp -R "/home/${USERNAME}" "/usr/jails/${JAILNAME}/home/"
	chown -R "${USERNAME}":"${USERNAME}" /usr/jails/"${JAILNAME}"/home/"${USERNAME}"
	rm "/usr/jails/${JAILNAME}/home/${USERNAME}/"session_*
	sed '$d' "/usr/jails/${JAILNAME}/home/${USERNAME}/.profile" | sed '$d' | sed '$d' > "/usr/jails/${JAILNAME}/home/${USERNAME}/.new_profile"
	rm "/usr/jails/${JAILNAME}/home/${USERNAME}/".profile
	mv "/usr/jails/${JAILNAME}/home/${USERNAME}/".new_profile "/usr/jails/${JAILNAME}/home/${USERNAME}/".profile
	jexec "${JAILNAME}" /bin/tcsh -c 'pwd_mkdb -p /etc/master.passwd'

	echog "Installing LXDE environment inside '${JAILNAME}' jail..."
	jexec "${JAILNAME}" /bin/tcsh -c 'setenv ASSUME_ALWAYS_YES yes; pkg install nano'
	jexec "${JAILNAME}" /bin/tcsh -c 'setenv ASSUME_ALWAYS_YES yes; pkg install xorg'
	jexec "${JAILNAME}" /bin/tcsh -c 'setenv ASSUME_ALWAYS_YES yes; pkg install lxde-meta'

	echog "Installing VirtualBox guest support inside '${JAILNAME}' jail..."
	jexec "${JAILNAME}" /bin/tcsh -c 'setenv ASSUME_ALWAYS_YES yes; pkg install virtualbox-ose-additions'
	echo 'vboxguest_enable="YES"' >> /usr/jails/"${JAILNAME}"/etc/rc.conf
	echo 'vboxservice_enable="YES"' >> /usr/jails/"${JAILNAME}"/etc/rc.conf
	echo 'vboxservice_flags="--disable-timesync"' >> /usr/jails/"${JAILNAME}"/etc/rc.conf

	echog "Configuring xinit to start LXDE automatically..."
	sed -i '' '/^twm.*/d' /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc
	sed -i '' '/^xclock.*/d' /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc
	sed -i '' '/^xterm.*/d' /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc
	sed -i '' '/^exec.*/d' /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc

	echog "Configuring xinit to raise mixer volume on startup..."
	echo "mixer vol 100" >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc
	echo "mixer pcm 100" >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc
	echo "mixer video 100" >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc
	echo "exec lxsession" >> /usr/jails/"${JAILNAME}"/usr/local/etc/X11/xinit/xinitrc

	echog "Generating DBUS machine UUID for '${JAILNAME}' jail..."
	jexec "${JAILNAME}" /bin/tcsh -c 'dbus-uuidgen --ensure'
fi

echog "All done!"
cd "${DIR}"
