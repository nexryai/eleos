# COPR SCM ("make srpm") build method.
#
# COPR clones the repository at the package's committish and runs:
#   make -f .copr/Makefile srpm outdir="<resultdir>" spec="<spec path>"
#
# The RPM version is derived from the checked-out git tag, so tagged releases
# do not require a committed version bump. Builds from a branch fall back to
# the Version in the spec file.

SPEC   := eleos.spec
TOPDIR := $(CURDIR)/_build
OUTDIR := $(if $(outdir),$(outdir),.)

srpm:
	@command -v rpmbuild >/dev/null 2>&1 && \
		command -v spectool >/dev/null 2>&1 && \
		command -v git >/dev/null 2>&1 || \
		dnf -y install rpm-build rpmdevtools git
	@set -e; \
	mkdir -p '$(TOPDIR)/SOURCES' '$(OUTDIR)'; \
	version="$$(git describe --tags --exact-match 2>/dev/null | sed 's/^v//')"; \
	spec='$(SPEC)'; \
	if [ -n "$$version" ]; then \
		sed "s/^Version:.*/Version:        $$version/" '$(SPEC)' > '$(TOPDIR)/$(SPEC)'; \
		spec='$(TOPDIR)/$(SPEC)'; \
	fi; \
	spectool -g -R --define "_topdir $(TOPDIR)" "$$spec"; \
	rpmbuild -bs --define "_topdir $(TOPDIR)" "$$spec"; \
	cp $(TOPDIR)/SRPMS/*.src.rpm '$(OUTDIR)'

.PHONY: srpm
