# ===========
# Build stage
# ===========
FROM golang:1.26.10-alpine3.23 AS builder

WORKDIR /code

# Pre-install dependencies to cache them as a separate image layer
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . /code
RUN go build -o certificator ./cmd/certificator

# ===========
# Final stage
# ===========
FROM alpine:3.23

WORKDIR /app
RUN apk --no-cache add ca-certificates-bundle=20261020-r0 curl

COPY ./fixtures /app/fixtures
COPY ./domains.yml /app/fixtures/domains.yml

COPY --from=builder /code/certificator .

CMD [ "./certificator" ]
