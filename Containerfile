FROM docker.io/library/golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/provisioner ./cmd/provisioner

FROM scratch
COPY --from=build /out/provisioner /provisioner
ENV PROVISIONER_DATA=/data \
    HOME=/config
VOLUME ["/data", "/config"]
EXPOSE 8444
ENTRYPOINT ["/provisioner"]
CMD ["serve"]
