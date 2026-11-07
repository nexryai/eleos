# COPR builds this spec through the SCM "make srpm" method
# (see .copr/Makefile).
Name:           roscaelum
Version:        0.7.0
Release:        1%{?dist}
Summary:        Lightweight nftables firewall that operates via netlink

License:        MIT
URL:            https://github.com/nexryai/roscaelum
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  golang >= 1.21

# The binary is a self-contained static Go binary; do not generate
# debuginfo/debugsource subpackages.
%global debug_package %{nil}

%description
roscaelum is a lightweight, simple, secure and essential firewall that
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

go build -buildvcs=false -trimpath -ldflags "-s -w" -o rcfctl .

%check
export CGO_ENABLED=0
export GOFLAGS=-mod=mod
# Fedora sets GOTOOLCHAIN=local in the build environment, but the chroot's
# Go may be older than the version required by go.mod. Allow downloading it,
# like in the build section.
export GOTOOLCHAIN=auto

go test ./...

%install
install -Dpm0755 rcfctl %{buildroot}%{_bindir}/rcfctl
install -Dpm0644 systemd/roscaelum.service %{buildroot}%{_prefix}/lib/systemd/system/roscaelum.service
install -Dpm0644 config.default.yml %{buildroot}%{_sysconfdir}/roscaelum.yml

%post
systemctl daemon-reload >/dev/null 2>&1 || :

%preun
if [ $1 -eq 0 ]; then
    systemctl stop roscaelum.service >/dev/null 2>&1 || :
    systemctl disable roscaelum.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -eq 1 ]; then
    systemctl try-restart roscaelum.service >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/rcfctl
%{_prefix}/lib/systemd/system/roscaelum.service
%config(noreplace) %{_sysconfdir}/roscaelum.yml

%changelog
* Sat Nov 07 2026 nexryai <nexryai@users.noreply.github.com> - 0.7.0-1
- Initial packaging for COPR
