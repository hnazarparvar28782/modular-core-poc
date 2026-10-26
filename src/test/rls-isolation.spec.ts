import { Pool } from 'pg';
import * as crypto from 'node:crypto';

/**
 * RLS isolation tests.
 * These tests run against a live dockerized Postgres (see docker-compose.yml)
 * and require NO running NestJS server - they only use pg directly.
 *
 * Run: npm run test:rls
 */
jest.setTimeout(30000);

const DATABASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://pocadmin:pocsecret@localhost:5432/modularpoc';

let pool: Pool;
let tenantA: string;
let tenantB: string;
let actorA: string;
let actorB: string;

async function resetTenant(client: any) {
  await client.query("SELECT set_config('app.current_tenant', '', true)");
}

beforeAll(async () => {
  pool = new Pool({ connectionString: DATABASE_URL, max: 5 });
  const c = await pool.connect();
  try {
    // Pick the two seeded tenants.
    const rows = (await c.query("SELECT id FROM tenants WHERE slug IN ('acme','globex') ORDER BY slug")).rows;
    if (rows.length < 2) throw new Error('seed tenants missing - check init.sql');
    tenantA = rows[0].id;
    tenantB = rows[1].id;
  } finally {
    c.release();
  }
  actorA = 'alice@acme.test';
  actorB = 'bob@globex.test';
});

afterAll(async () => {
  if (pool) await pool.end();
});

/** Run fn in a tx scoped to a tenant, like DatabaseService.withTenant */
async function withTenant<T>(tenantId: string, actor: string, fn: (c: any) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.current_tenant', $1, true)", [tenantId]);
    await client.query("SELECT set_config('app.current_actor', $1, true)", [actor]);
    const r = await fn(client);
    await client.query('COMMIT');
    return r;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw e;
  } finally {
    client.release();
  }
}

describe('Row Level Security tenant isolation', () => {
  let recordA: string;

  beforeEach(async () => {
    const client = await pool.connect();
    try {
      await client.query('DELETE FROM records WHERE title LIKE $1', ['rls-test-%']);
    } finally {
      client.release();
    }
  });

  it('tenant A cannot see rows created by tenant B', async () => {
    recordA = await withTenant(tenantA, actorA, async (c) => {
      const r = await c.query(
        'INSERT INTO records (tenant_id, title, body, amount) VALUES ($1,$2,$3,$4) RETURNING id',
        [tenantA, 'rls-test-A1', 'secret of A', 100],
      );
      return r.rows[0].id;
    });
    await withTenant(tenantB, actorB, async (c) => {
      await c.query(
        'INSERT INTO records (tenant_id, title, body, amount) VALUES ($1,$2,$3,$4)',
        [tenantB, 'rls-test-B1', 'secret of B', 200],
      );
    });

    const visibleToB = await withTenant(tenantB, actorB, async (c) =>
      (await c.query('SELECT id FROM records')).rows.map((r: any) => r.id),
    );
    expect(visibleToB).not.toContain(recordA);

    const visibleToA = await withTenant(tenantA, actorA, async (c) =>
      (await c.query('SELECT id FROM records')).rows.map((r: any) => r.id),
    );
    expect(visibleToA).toContain(recordA);
  });

  it('cross-tenant UPDATE and DELETE by id are no-ops', async () => {
    const upd = await withTenant(tenantB, actorB, async (c) =>
      c.query('UPDATE records SET amount = 999999 WHERE id = $1 RETURNING id', [recordA]),
    );
    expect(upd.rowCount).toBe(0);

    const del = await withTenant(tenantB, actorB, async (c) =>
      c.query('DELETE FROM records WHERE id = $1', [recordA]),
    );
    expect(del.rowCount).toBe(0);
  });

  it('INSERT with a foreign tenant_id violates the RLS WITH CHECK policy', async () => {
    await expect(
      withTenant(tenantB, actorB, async (c) =>
        c.query(
          'INSERT INTO records (tenant_id, title, amount) VALUES ($1,$2,$3)',
          [tenantA, 'rls-test-smuggle', 1],
        ),
      ),
    ).rejects.toThrow(/row-level security|WITH CHECK|violates/i);
  });

  it('without any tenant context, zero rows are visible (fail closed)', async () => {
    const client = await pool.connect();
    try {
      await resetTenant(client);
      const r = await client.query('SELECT count(*)::int AS n FROM records');
      expect(r.rows[0].n).toBe(0);
    } finally {
      client.release();
    }
  });

  it('SET LOCAL resets tenant scope at commit (no connection-pool leak)', async () => {
    await withTenant(tenantA, actorA, async () => undefined);
    const client = await pool.connect();
    try {
      const cur = await client.query(
        "SELECT current_setting('app.current_tenant', true) AS t",
      );
      expect(cur.rows[0].t === '' || cur.rows[0].t === null).toBe(true);
    } finally {
      client.release();
    }
  });

  it('tampered record cannot be approved without a matching HITL approval digest', async () => {
    // craft correct digest for record payload
    const payload = await withTenant(tenantA, actorA, async (c) => {
      const r = await c.query('SELECT title, body, amount FROM records WHERE id = $1', [recordA]);
      const row = r.rows[0];
      return `${row.title}|${row.body ?? ''}|${row.amount}`;
    });
    const digest = crypto.createHash('sha256').update(payload).digest('hex');

    await expect(
      withTenant(tenantA, actorA, async (c) =>
        c.query("UPDATE records SET status = 'approved' WHERE id = $1", [recordA]),
      ),
    ).rejects.toThrow(/HITL violation|row-level security|permission denied/i);

    // with a matching approved approval row, the update succeeds
    await withTenant(tenantA, actorA, async (c) => {
      await c.query(
        "INSERT INTO approvals (tenant_id, record_id, requested_by, approver, status, payload_hash) VALUES ($1,$2,$3,$4,'approved',$5)",
        [tenantA, recordA, actorA, 'human-approver-1', digest],
      );
      await c.query("UPDATE records SET status = 'approved' WHERE id = $1", [recordA]);
    });
  });

  it('audit_log is append-only (UPDATE/DELETE blocked)', async () => {
    const id = await withTenant(tenantA, actorA, async (c) => {
      const r = await c.query(
        "INSERT INTO audit_log (tenant_id, action, actor, payload_hash) VALUES ($1,'test',$2,'deadbeef') RETURNING id",
        [tenantA, actorA],
      );
      return r.rows[0].id as string;
    });
    await expect(
      withTenant(tenantA, actorA, async (c) =>
        c.query('UPDATE audit_log SET payload_hash = $1 WHERE id = $2', ['evil', id]),
      ),
    ).rejects.toThrow(/append-only|permission denied/i);
  });
});
