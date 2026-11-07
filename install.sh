#!/usr/bin/env bash

set -e

required_commands=("wget" "curl" "unzip" "nft")

for cmd in "${required_commands[@]}"; do
    if command -v "$cmd" > /dev/null 2>&1; then
        echo "Checking $cmd >> OK!"
    else
        echo "$cmd is not installed. Please install it first."
        exit 1
    fi
done

ARCHITECTURE=$(uname -m)

case $ARCHITECTURE in
    x86_64)
        ARCH="amd64"
        ;;
    armv7l)
        ARCH="arm"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
    mips64)
        ARCH="mips64"
        ;;
    *)
        echo "Unsupported ARCHITECTURE >_< : $ARCHITECTURE"
        exit 1
        ;;
esac

ZIPNAME="roscaelum-linux-$ARCH.zip"
FILENAME="rcfctl-$ARCH"

wget "https://github.com/nexryai/roscaelum/releases/latest/download/$ZIPNAME"
unzip $ZIPNAME
rm $ZIPNAME
mv $FILENAME /usr/bin/rcfctl

curl https://raw.githubusercontent.com/nexryai/roscaelum/main/systemd/roscaelum.service > /etc/systemd/system/roscaelum.service

if [ ! -f /etc/roscaelum.yml ]; then
  curl https://raw.githubusercontent.com/nexryai/roscaelum/main/config.default.yml > /etc/roscaelum.yml
fi

# restoreconがあるならSELinuxに怒られないようにする
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R /usr/bin/rcfctl
fi

systemctl daemon-reload

echo "roscaelum has been installed successfully. enjoy! :)"
