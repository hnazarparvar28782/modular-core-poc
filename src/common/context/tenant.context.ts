import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'node:async_hooks';

export interface TenantContextValue {
  tenantId: string;
  actor: string;
  role: string;
}

/**
 * Async-local tenant context.
 * The tenant id is the single source of truth used by DatabaseService to
 * issue `SET LOCAL app.current_tenant = ...` on every transaction.
 */
@Injectable()
export class TenantContext {
  private readonly als = new AsyncLocalStorage<TenantContextValue>();

  run<T>(ctx: TenantContextValue, fn: () => T): T {
    return this.als.run(ctx, fn);
  }

  get(): TenantContextValue {
    const ctx = this.als.getStore();
    if (!ctx) {
      throw new Error('TenantContext: no tenant context bound to this execution');
    }
    return ctx;
  }

  tryGet(): TenantContextValue | undefined {
    return this.als.getStore();
  }

  get tenantId(): string {
    return this.get().tenantId;
  }

  get actor(): string {
    return this.get().actor;
  }
}

/** Standalone helper usable outside Nest DI (tests, scripts). */
export const tenantContext = new TenantContext();
