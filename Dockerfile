# Builds from source - for local development (`docker build .`). The
# release pipeline uses Dockerfile.goreleaser instead, which copies the
# already cross-compiled binary rather than rebuilding it.
# syntax=docker/dockerfile:1
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/baromio-probe ./cmd/baromio-probe
RUN mkdir -p /var/lib/baromio-probe && chown 65532:65532 /var/lib/baromio-probe

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/baromio-probe /baromio-probe
# distroless has no shell to mkdir/chown the volume target, so its
# ownership is prepared in the build stage above and copied in - without
# this, the nonroot user cannot write to the volume Docker creates for it
# on first run.
COPY --from=build --chown=65532:65532 /var/lib/baromio-probe /var/lib/baromio-probe
VOLUME ["/var/lib/baromio-probe"]
ENV BAROMIO_DATA_DIR=/var/lib/baromio-probe
USER nonroot:nonroot
ENTRYPOINT ["/baromio-probe"]
