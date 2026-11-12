# ShorStop container image. Built by GoReleaser (dockers_v2 in
# .goreleaser.yaml), which puts each platform's static binary in the build
# context under <os>/<arch>/; this file only packages it.
#
#   docker run --rm -v "$PWD:/src" ghcr.io/shorstophq/shorstop
#   docker run --rm -v "$PWD:/src" ghcr.io/shorstophq/shorstop scan --format sarif > shorstop.sarif
#
# FROM scratch: the image holds nothing but the binary. ShorStop is static
# (CGO_ENABLED=0), makes no network calls and needs no CA certificates,
# shell, libc or user database, so there's nothing else to patch or scan.
FROM scratch

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/shorstop /shorstop
COPY LICENSE /LICENSE

# Not root: an unprivileged numeric user (scratch has no /etc/passwd, and
# none is needed). Reading a mounted repository works with the usual file
# permissions. To write reports into the mount, redirect stdout as above or
# run with --user "$(id -u):$(id -g)".
USER 65532:65532

WORKDIR /src
ENTRYPOINT ["/shorstop"]
CMD ["scan", "."]
