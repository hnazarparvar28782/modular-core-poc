# modular-core-poc

NestJS/TypeScript PoC for **multi-tenant Row Level Security (RLS)** and **HITL (Human-in-the-Loop) integrity** tests.

## What's inside

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Local Postgres 16 with auto-init via `/docker-entrypoint-initdb.d` |
| `Dockerfile` | Optional simple multi-stage NestJS build |
| `init.sql` / `src/database/init.sql` | Schema: RLS policies, pgcrypto (`gen_random_uuid()`), HITL approval trigger, append-only audit log |
| `src/common/context/tenant.context.ts` | AsyncLocalStorage tenant context |
| `src/database/database.service.ts` | pg Pool + `withTenant()` issuing `SET LOCAL app.current_tenant` inside transactions |
| `src/test/rls-isolation.spec.ts` | Tenant isolation tests (read/write/insert/delete cross-tenant, fail-closed) |
| `src/test/hitl-tamper.spec.ts` | Tamper-evidence tests (approval digest, blocked approvals, hash-chained audit log) |
| `src/main.ts`, `src/app.module.ts` | Minimal NestJS app (tests do NOT need the server running) |

## Requirements

- Node 20+
- Docker + Docker Compose

## Run

```bash
# 1. start the database (init.sql runs automatically on first boot)
docker compose up -d

# 2. install deps
npm install

# 3. run all tests
npm test

# or individually
npm run test:rls
npm run test:hitl
```

Connection string (already wired, no placeholders):

```
DATABASE_URL=postgresql://pocadmin:pocsecret@localhost:5432/modularpoc
```

The tests connect as the non-superuser role `poc_app` so PostgreSQL itself
enforces RLS — not application code.

## Design notes

- **Tenant scoping**: every transaction runs `SELECT set_config('app.current_tenant', $1, true)` (`SET LOCAL`), so pooled connections can never leak a tenant scope.
- **Fail closed**: with no tenant context set, RLS returns zero rows.
- **HITL integrity**: a record can only become `approved` if an `approvals` row exists whose `payload_hash` equals the SHA-256 digest of the current record payload — enforced by the `trg_record_approval_guard` trigger.
- **Tamper evidence**: `audit_log` is hash-chained and append-only (UPDATE/DELETE rejected by trigger).

## Reset database

```bash
docker compose down -v   # removes the pgdata volume
docker compose up -d
```
