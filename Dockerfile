# syntax=docker/dockerfile:1.7
# Static binary on distroless: no shell, no package manager, non-root. ~20 MB.
FROM golang:1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/irg ./cmd/irg

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/irg /irg
USER 65532:65532
EXPOSE 8080 9090 9100
HEALTHCHECK --interval=30s --timeout=3s CMD ["/irg", "health"]
ENTRYPOINT ["/irg"]
CMD ["all"]
