FROM golang:alpine as builder

RUN apk update && apk add --no-cache git make gcc libc-dev

# download, cache and install deps
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

# copy and compiled the app
COPY . .
RUN make ditto

# start a new stage from scratch
FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# copy the prebuilt binary from the builder stage
COPY --from=builder /app/_build/ditto .
COPY --from=builder /app/send-email-report.sh /usr/bin/

ENTRYPOINT ["./ditto"]
