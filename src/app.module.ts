import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { GlobalModule } from './global.module';
import { AuthModule } from './auth/auth.module';
import { HealthModule } from './health/health.module';
import { HelmetModule } from './helmet';
import { ScheduleModule } from '@nestjs/schedule';
import { UserModule } from './user/user.module';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [
    GlobalModule,
    HealthModule,
    HelmetModule.forRoot({
      contentSecurityPolicy: false,
    }),
    ScheduleModule.forRoot(),
    UserModule,
    AuthModule,
    EventEmitterModule.forRoot(),
    HttpModule.register({
      timeout: 5000,
      maxRedirects: 5,
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
