# Build en dos fases — imagen final ~10 MB sin el compilador de Rust

FROM rust:1.76-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Truco: compilar dependencias primero para cachearlas
RUN mkdir src && echo "fn main(){}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY src ./src
COPY migrations ./migrations
RUN touch src/main.rs && cargo build --release

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
RUN adduser -D -H vaultuser

WORKDIR /app
COPY --from=builder /app/target/release/vault-api .
COPY --from=builder /app/migrations ./migrations

USER vaultuser
EXPOSE 8080
CMD ["./rustvault-api"]
