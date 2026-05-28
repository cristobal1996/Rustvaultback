.PHONY: help db db-stop db-reset run build test check fmt seed logs psql

help:
	@echo ""
	@echo "  make db        → Arranca PostgreSQL con Docker"
	@echo "  make db-stop   → Para PostgreSQL"
	@echo "  make db-reset  → Borra y recrea la BD"
	@echo "  make run       → Arranca el servidor"
	@echo "  make build     → Compila en modo release"
	@echo "  make test      → Ejecuta los tests"
	@echo "  make check     → Comprueba errores sin compilar"
	@echo "  make fmt       → Formatea el código"
	@echo "  make seed      → Inserta datos de prueba"
	@echo "  make logs      → Ver logs de PostgreSQL"
	@echo "  make psql      → Abre consola psql"
	@echo ""

db:
	docker compose up -d postgres
	@echo "Esperando a PostgreSQL..."
	@sleep 2
	@echo "PostgreSQL listo en localhost:5432"

db-stop:
	docker compose stop postgres

db-reset:
	@echo "ADVERTENCIA: Se borrarán todos los datos. Ctrl+C para cancelar."
	@sleep 3
	docker compose down -v
	docker compose up -d postgres
	@sleep 2
	@echo "BD reseteada"

run: db
	cargo run

build:
	cargo build --release

check:
	cargo check

fmt:
	cargo fmt

test:
	cargo test

seed: db
	@echo "Insertando datos de prueba..."
	PGPASSWORD=rustvaultpass psql -h localhost -U rustvaultuser -d rustvaultdb -f seeds/dev.sql
	@echo "Seeds insertados"

logs:
	docker compose logs -f postgres

psql:
	PGPASSWORD=rustvaultpass psql -h localhost -U rustvaultuser -d rustvaultdb
