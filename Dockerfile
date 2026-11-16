FROM rust:1.99.1-alpine3.24 AS builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.24.4
RUN apk upgrade --no-cache && \
  apk add --no-cache ca-certificates
USER 10000:10000
COPY --from=builder /app/target/release/persona-idp /usr/bin/persona-idp
ENTRYPOINT ["/usr/bin/persona-idp"]
