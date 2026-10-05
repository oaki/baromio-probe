# syntax=docker/dockerfile:1
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/baromio-probe ./cmd/baromio-probe

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/baromio-probe /baromio-probe
VOLUME ["/var/lib/baromio-probe"]
ENV BAROMIO_DATA_DIR=/var/lib/baromio-probe
USER nonroot:nonroot
ENTRYPOINT ["/baromio-probe"]
