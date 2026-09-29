FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /demo ./cmd/demo && mkdir /pki

# distroless/static ships CA roots (for api.anthropic.com). /pki is created
# owned by the nonroot user so a fresh named volume mounted there is writable.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /demo /demo
COPY --from=build --chown=65532:65532 /pki /pki
ENV PKI_DIR=/pki PORT=8080
ENTRYPOINT ["/demo"]
CMD ["supervise"]
