# One static binary for every role. The build runs on the builder's own platform and
# cross-compiles, so an arm64 image needs no emulation.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26 AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/rhcl-probe .

# distroless: no shell, no package manager, CA certificates included. Runs as any UID,
# which is what OpenShift's restricted-v2 SCC assigns.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rhcl-probe /rhcl-probe
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/rhcl-probe"]
