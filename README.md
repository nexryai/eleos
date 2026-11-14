# eleos firewall

## What is this?
A lightweight, simple, secure and essential firewall that operates nftables
directly via netlink.
Under development.

## Design principles

#### Simple and easy to use
All configuration is managed in YAML. No more hammering `ufw status`!

#### Secure
It warns about unsafe settings. It is written in memory-safe Go.

#### Plenty of useful features
It includes features that help make your server more secure, such as
allowing access only on specific interfaces and denying access from
arbitrary IP addresses.
Want to build your own router? eleos includes features to help you
set up a simple home router!

## Usage
> [!CAUTION]
> disable any existing firewall before using this.

### Install with snap
<a href="https://snapcraft.io/eleos" target="_blank">
   <img width="200px" height="auto" alt="Get it from the Snap Store" src=https://snapcraft.io/en/dark/install.svg />
</a>

　  


This snap runs strictly confined. The privileged firewall-control interface has to be connected manually before rules can be applied:

```sh
sudo snap connect eleos:firewall-control
```

Configuration lives in:
```
/var/snap/eleos/current/eleos.yml
```

Edit the configuration, then enable the service to apply rules now and at boot:

```sh
sudo snap start --enable eleos.daemon
```

The service applies rules once and exits; no process watches the configuration.
After editing, run `sudo eleos.elctl apply`. Stop and disable the service with
`sudo snap stop --disable eleos.daemon`; stopping an active service removes its rules.
Existing installations keep their service enablement when refreshed.

### Install from dnf repositories
If you are using one of the following distributions, you can install it from the [Official Copr](https://copr.fedorainfracloud.org/coprs/nexryai/eleos/).

 - Fedora
 - RHEL
 - Alma Linux
 - Rocky Linux
 - CentOS Stream
 - Amazon Linux
 - Azure Linux
 - openEuler
 - openSUSE


```sh
sudo dnf copr enable nexryai/eleos
sudo dnf install eleos

# Edit the rules
sudo nano /etc/eleos.yml

sudo elctl enable
sudo systemctl enable eleos
```

### Install from the APT repository
Packages for Debian-based distributions are served from GitHub Pages:

```sh
curl -fsSL https://nexryai.github.io/eleos/eleos-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/eleos-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/eleos-archive-keyring.gpg] https://nexryai.github.io/eleos/ stable main" \
  | sudo tee /etc/apt/sources.list.d/eleos.list

sudo apt update
sudo apt install eleos

# Edit the rules
sudo nano /etc/eleos.yml

sudo elctl enable
sudo systemctl enable eleos
```

### Install from the pacman repository (Arch Linux)

Packages for `x86_64` and `aarch64` are published to a signed pacman
repository on GitHub Pages. Import the repository key (the same key used for
the APT repository), then add the repository:

```sh
curl -fsSL https://nexryai.github.io/eleos/pacman/eleos-archive-keyring.asc \
  -o /tmp/eleos-archive-keyring.asc
sudo pacman-key --add /tmp/eleos-archive-keyring.asc
sudo pacman-key --lsign-key 4795EA54BDDDEAA6C8145A1EB482297ABFCE2726

sudo tee -a /etc/pacman.conf >/dev/null <<'EOF'
[eleos]
SigLevel = Required DatabaseRequired
Server = https://nexryai.github.io/eleos/pacman/$arch
EOF

sudo pacman -Syu
sudo pacman -S eleos

# Edit the rules
sudo nano /etc/eleos.yml

sudo elctl enable
sudo systemctl enable eleos
```

If the repository key is ever rotated, check the published
[signing-key fingerprint](https://nexryai.github.io/eleos/eleos-archive-keyring.fingerprint).

#### Install from source
```sh
# Build
CGO_ENABLED=0 go build -o elctl main.go

# Install (run as root)
install -m 0755 elctl /usr/bin/elctl
install -m 0644 systemd/eleos.service /etc/systemd/system/
install -m 0644 config.default.yml /etc/eleos.yml
systemctl daemon-reload

# Edit the rules
nano /etc/eleos.yml

# Apply
elctl enable

# Apply automatically on boot
systemctl enable eleos
```

After editing the configuration, re-apply it with `elctl apply`.

## Known issues

### On RHEL-based systems, systemd may complain about permissions
This is caused by SELinux.
`sudo restorecon -R /usr/bin/elctl` fixes it.

#### Conflicts with Docker
Set `allowAllFwd` to `true` to work around it.
