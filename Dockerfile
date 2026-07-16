# Used by goreleaser's dockers_v2 pipe: the smithmark binary is already
# built (CGO disabled, cross compiled per target) before this runs, so the
# image only packages it. GoReleaser stages prebuilt binaries under a
# TARGETPLATFORM directory in the build context, so COPY reaches for that
# path rather than a bare binary name.
FROM gcr.io/distroless/static:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/smithmark /smithmark
ENTRYPOINT ["/smithmark"]
