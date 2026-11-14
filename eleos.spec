# COPR builds this spec through the SCM "make srpm" method
# (see .copr/Makefile).
Name:           eleos
Version:        0.8.7
Release:        1%{?dist}
Summary:        Lightweight nftables firewall that operates via netlink

License:        MIT
URL:            https://github.com/nexryai/eleos
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  golang >= 1.21
# Needed so Go can verify TLS when downloading modules/toolchains.
BuildRequires:  ca-certificates

# The binary is a self-contained static Go binary; do not generate
# debuginfo/debugsource subpackages.
%global debug_package %{nil}

%description
eleos is a lightweight, simple, secure and essential firewall that
manipulates nftables directly through netlink. It does not depend on the
nft(8) command and needs no external API access to generate or apply
rules, so it works fully offline.

%prep
%autosetup -n %{name}-%{version}

%build
export CGO_ENABLED=0
export GOFLAGS=-mod=mod
# Allow the Go toolchain to download the version required by go.mod when
# the distribution packages an older Go (requires internet access).
# Microsoft's Go (Azure Linux) refuses GOTOOLCHAIN=auto unless the following
# variable is set; it is ignored by other Go distributions.
export MS_GOTOOLCHAIN_ALLOW_NON_LOCAL=1
export GOTOOLCHAIN=auto

%ifarch x86_64
%global goarch amd64
%endif
%ifarch aarch64
%global goarch arm64
%endif
%ifarch ppc64le
%global goarch ppc64le
%endif
%ifarch s390x
%global goarch s390x
%endif
%ifarch riscv64
%global goarch riscv64
%endif
%{?goarch:export GOARCH=%{goarch}}

go build -buildvcs=false -trimpath -ldflags "-s -w" -o elctl .

%check
export CGO_ENABLED=0
export GOFLAGS=-mod=mod
# Fedora sets GOTOOLCHAIN=local in the build environment, but the chroot's
# Go may be older than the version required by go.mod. Allow downloading it,
# like in the build section. See also the Microsoft Go note there.
export MS_GOTOOLCHAIN_ALLOW_NON_LOCAL=1
export GOTOOLCHAIN=auto

go test ./...

%install
install -Dpm0755 elctl %{buildroot}%{_bindir}/elctl
install -Dpm0644 systemd/eleos.service %{buildroot}%{_prefix}/lib/systemd/system/eleos.service
install -Dpm0644 config.default.yml %{buildroot}%{_sysconfdir}/eleos.yml

%post
systemctl daemon-reload >/dev/null 2>&1 || :

%preun
if [ $1 -eq 0 ]; then
    systemctl stop eleos.service >/dev/null 2>&1 || :
    systemctl disable eleos.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -eq 1 ]; then
    systemctl try-restart eleos.service >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/elctl
%{_prefix}/lib/systemd/system/eleos.service
%config(noreplace) %{_sysconfdir}/eleos.yml

%changelog
* Wed Nov 11 2026 nexryai <nexryai@users.noreply.github.com> - 0.8.5-1
- Publish a signed APT repository on GitHub Pages

* Mon Nov 09 2026 nexryai <nexryai@users.noreply.github.com> - 0.8.4-1
- Update README and default configuration

* Mon Nov 09 2026 nexryai <nexryai@users.noreply.github.com> - 0.8.3-1
- Require ca-certificates so Go can verify TLS on minimal chroots
  (e.g. Azure Linux)

* Mon Nov 09 2026 nexryai <nexryai@users.noreply.github.com> - 0.8.2-1
- Allow GOTOOLCHAIN=auto with the Microsoft build of Go (Azure Linux)

* Mon Nov 09 2026 nexryai <nexryai@users.noreply.github.com> - 0.8.1-1
- New release with corrected snap packaging

* Mon Nov 09 2026 nexryai <nexryai@users.noreply.github.com> - 0.8.0-1
- Rename the project and package to eleos, and the command to elctl

* Sat Nov 07 2026 nexryai <nexryai@users.noreply.github.com> - 0.7.1-1
- Run the check phase with GOTOOLCHAIN=auto so chroots with an older Go
  toolchain can build

* Sat Nov 07 2026 nexryai <nexryai@users.noreply.github.com> - 0.7.0-1
- Initial packaging for COPR
