## roscaelum Firewall

### What is this?
A lightweight, simple, secure and essential firewall that operates nftables
directly via netlink.
Under development.

### Design principles

#### Simple and easy to use
All configuration is managed in YAML. No more hammering `ufw status`!
It also runs as a single binary and does not depend on the `nft` command,
so installation is easy.

#### Secure
It warns about unsafe settings. It is written in memory-safe Go.

#### Plenty of useful features
It includes features that help make your server more secure, such as
allowing access only on specific interfaces and denying access from
arbitrary IP addresses.
Want to build your own router? roscaelum includes features to help you
set up a simple home router!

#### Fully offline operation
No external API communication is required, so rules can be generated and
applied entirely offline.

### Usage
Note: disable any existing firewall before using this.

#### Install from source
```sh
# Build
CGO_ENABLED=0 go build -o rcfctl main.go

# Install (run as root)
install -m 0755 rcfctl /usr/bin/rcfctl
install -m 0644 systemd/roscaelum.service /etc/systemd/system/
install -m 0644 config.default.yml /etc/roscaelum.yml
systemctl daemon-reload

# Edit the rules
nano /etc/roscaelum.yml

# Apply
rcfctl enable

# Apply automatically on boot
systemctl enable roscaelum
```

After editing the configuration, re-apply it with `rcfctl apply`.

### Known issues

#### On RHEL-based systems, systemd may complain about permissions
This is caused by SELinux.
`sudo restorecon -R /usr/bin/rcfctl` fixes it.

#### Conflicts with Docker
Set `allowAllFwd` to `true` to work around it.
