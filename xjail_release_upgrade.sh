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

read -p "${YELLOW}This script will help you upgrade your current FreeBSD release to the specified release version number. Basejail will also be upgraded to specified release version. After release upgrade is done, run standard xjail_update.sh script to build your fresh new xjails kernel. Continue? [N]${RESET} " ANSWER
case "${ANSWER}" in
	[Yy]* ) echo;;
	[Nn]* ) exit;;
	* ) exit;;
esac

echo
echog "Upgrade steps:"
echog "1) update host packages, system, update basejail (automatic)"
echog "2) upgrade host system (semi-automatic)"
echog "3) upgrade basejail and prepare for normal operation (automatic)"

read -p "${YELLOW}Enter step number you would like to perform: ${RESET}" STEP

echo
echo "Step ${STEP}"
echo "======"

case "${STEP}" in
	1 ) echog "Updating host packages, system, and updating basejail..."
		pkg update
		yes | pkg upgrade
		set +e
		freebsd-update fetch
		freebsd-update install
		mkdir -p /basejail
		mount -t nullfs /usr/jails/basejail/ /basejail
		ezjail-admin update -u
		umount /basejail
		echog "Update done. Reboot your machine and continue with step 2."
	;;
	2 ) read -p "${YELLOW}Enter release number you would like to upgrade to (for example 11.1, omit the -RELEASE suffix): ${RESET}" UPGRADETO
		echog "Upgrading host system to ${UPGRADETO}-RELEASE..."
		freebsd-update upgrade -r "${UPGRADETO}-RELEASE"
		freebsd-update install
		echo
		echog "NOTE your previous system version you just upgraded from! ${VERSION}"
		echog "Follow any instructions that were just displayed by freebsd-update install, reboot your machine and run 'freebsd-update install' until it prints there are no updates to install, and ALWAYS follow any instructions that are shown! When you are done, re-run this utility and continue with step 3."
		echo
		echog "If you get shared object errors at any later point, run 'pkg-static install -f pkg; pkg update; pkg upgrade' to fix ABI compatibility issues."
	;;
	3 )	echog "Upgrading basejail..."
		read -p "${YELLOW}Enter PREVIOUS system release that you noted in previous step (for example 11.0, omit the -RELEASE suffix): ${RESET}" UPGRADEFROM
		ezjail-admin update -U -s "${UPGRADEFROM}-RELEASE"

		echog "Deleting current release src..."
		find /usr/src -mindepth 1 -delete
		echog "Checking out new release src..."
		svn co https://svn.freebsd.org/base/releng/"$VERSION" /usr/src --non-interactive --trust-server-cert-failures=unknown-ca
		echo
		echog "All done! Now run xjail_update.sh script to build new XJAILS kernel and update your ports tree. Continue as if this system release was installed from the beginning."
	;;
	* ) echor "Invalid step number."; exit;;
esac
