import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { Pool, PoolClient, QueryResultRow } from 'pg';
import { TenantContext } from '../common/context/tenant.context';

export const DATABASE_URL =
  process.env.DATABASE_URL ??
  'postgresql://pocadmin:pocsecret@localhost:5432/modularpoc';

@Injectable()
export class DatabaseService implements OnModuleDestroy {
  private readonly logger = new Logger(DatabaseService.name);
  private readonly pool: Pool;

  constructor(private readonly tenantContext: TenantContext) {
    this.pool = new Pool({
      connectionString: DATABASE_URL,
      max: 10,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 10_000,
    });
    this.pool.on('error', (err) => this.logger.error('pg pool error', err));
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  async query<T extends QueryResultRow = any>(
    text: string,
    params: any[] = [],
  ): Promise<T[]> {
    const client = await this.pool.connect();
    try {
      const res = await client.query<T>(text, params);
      return res.rows;
    } finally {
      client.release();
    }
  }

  /**
   * Runs `fn` inside a transaction with the tenant context applied.
   * `SET LOCAL` guarantees the tenant is reset when the transaction ends,
   * so pooled connections can never leak a tenant scope.
   */
  async withTenant<T>(
    ctx: { tenantId: string; actor: string; role?: string },
    fn: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('app.current_tenant', $1, true)`, [ctx.tenantId]);
      await client.query(`SELECT set_config('app.current_actor', $1, true)`, [ctx.actor ?? 'unknown']);
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async withCurrentTenant<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const ctx = this.tenantContext.get();
    return this.withTenant(ctx, fn);
  }
}
