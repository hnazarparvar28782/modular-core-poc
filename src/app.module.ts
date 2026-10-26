import { Module } from '@nestjs/common';
import { TenantContext } from './common/context/tenant.context';
import { DatabaseService } from './database/database.service';

@Module({
  controllers: [],
  providers: [TenantContext, DatabaseService],
  exports: [TenantContext, DatabaseService],
})
export class AppModule {}
