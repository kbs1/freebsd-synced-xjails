#!/bin/sh

set -e

# sh compatible markup
GREEN="[0;32m"
YELLOW="[1;33m"
RED="[0;31m"
RESET="[0m"

WORKDIR=~/.xjails
cd "${WORKDIR}"

echog()
{
	echo "${GREEN}${1}${RESET}"
}

echor()
{
	echo "${RED}${1}${RESET}"
}

VERSION=`freebsd-version | grep -Eo '^[0-9.]+' | head -n 1`
echog "Detected system version: ${VERSION}"

read -p "${YELLOW}This script will update your FreeBSD release to the newest version. It will also optionally update the basejail, along with the ports tree. After the update, a custom XJAILS kernel will be rebuilt. Continue? [N]${RESET} " ANSWER
case "${ANSWER}" in
	[Yy]* ) echo;;
	[Nn]* ) exit;;
	* ) exit;;
esac

echog "Updating host system..."
freebsd-update fetch --not-running-from-cron
set +e
freebsd-update install
set -e

read -p "${YELLOW}Update basejail? Only do this on one machine, as you can then sync other machines via unison. [N]${RESET} " ANSWER
if [ "${ANSWER}" == "y" -o "${ANSWER}" == "Y" -o "${ANSWER}" == "yes" -o "${ANSWER}" == "YES" ]; then
	echog "Updating basejail..."

	# fix install complaining about nonexistent directories from outside of jails
	mkdir -p /basejail
	mount -t nullfs /usr/jails/basejail/ /basejail
	ezjail-admin update -u
	umount /basejail
fi

read -p "${YELLOW}Update jails ports tree? Only do this on one machine, as you can then sync other machines via unison. [N]${RESET} " ANSWER
if [ "${ANSWER}" == "y" -o "${ANSWER}" == "Y" -o "${ANSWER}" == "yes" -o "${ANSWER}" == "YES" ]; then
	echog "Updating jails ports tree..."
	ezjail-admin update -P
fi

read -p "${YELLOW}Update of xjails base / ports tree complete. Individual xjails can be updated via pkg or other means separately. Press return to continue.${RESET} " ANSWER

echog "Compiling new XJAILS kernel..."

# compile new kernel
if [ ! -d /usr/src/.svn ]; then
	# check out current release src
	echog "Checking out release src..."
	find /usr/src -mindepth 1 -delete
	svn co https://svn.freebsd.org/base/releng/"$VERSION" /usr/src --non-interactive --trust-server-cert-failures=unknown-ca
else
	echog "Updating release src..."
	cd /usr/src
	svn st | grep '^M' | cut -f2 -w - | xargs svn revert
	svn st | grep '^?' | cut -f2 -w - | xargs rm -fr
	svn up --non-interactive --trust-server-cert-failures=unknown-ca
	cd "${WORKDIR}"
fi

REVISION=`LANG=C svn info /usr/src | awk '/^Revision:/ {print $2;}'`

set +e
rm -f freebsd_"${VERSION}"_xjails.patch
set -e

# download kernel patch
echog "Downloading kernel XJAILS patch..."
wget http://kbs-development.com/download/freebsd_"${VERSION}"_xjails.patch

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

read -p "${YELLOW}Update process completed. System will now reboot. Press enter to continue, or CTRL-C to quit.${RESET} " ANSWER

reboot
