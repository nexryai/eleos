# COPR SCM ("make srpm") build method.
#
# COPR clones the repository and runs:
#   make -f .copr/Makefile srpm outdir="<resultdir>" spec="<spec path>"
#
# This target downloads the release tarball referenced by Source0 (it has
# network access even when the package builds themselves do not) and then
# creates the SRPM that COPR rebuilds in each chroot.

SPEC   := roscaelum.spec
TOPDIR := $(CURDIR)/_build
OUTDIR := $(if $(outdir),$(outdir),.)

srpm:
	@if ! command -v rpmbuild >/dev/null 2>&1 || ! command -v spectool >/dev/null 2>&1; then \
		dnf -y install rpm-build rpmdevtools; \
	fi
	mkdir -p $(TOPDIR)/SOURCES
	spectool -g -R --define "_topdir $(TOPDIR)" $(SPEC)
	rpmbuild -bs --define "_topdir $(TOPDIR)" $(SPEC)
	cp $(TOPDIR)/SRPMS/*.src.rpm $(OUTDIR)

.PHONY: srpm
