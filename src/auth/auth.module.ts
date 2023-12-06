import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
// import { UserService } from '../user/user.service';
// import { MailService } from '../mail/mail.service';
import { TokenService } from '../token/token.service';
import { AccessTokenStrategy } from './strategies/accessToken.strategy';
import { RefreshTokenStrategy } from './strategies/refreshToken.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { MicrosoftStratergy } from './strategies/microsoft.stratergy';
import { UserService } from 'src/user/user.service';

@Module({
  imports: [JwtModule.register({})],
  controllers: [AuthController],
  providers: [
    UserService,
    AuthService,
    // MailService,
    TokenService,
    RefreshTokenStrategy,
    AccessTokenStrategy,
    GoogleStrategy,
    MicrosoftStratergy,
  ],
})
export class AuthModule {}
