import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  UseGuards,
  Req,
  Res,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { EmailDto } from './dto/email.dto';
import { ResetPasswordDto } from './dto/reset.password.dto';
import { TokenDto } from './dto/token.dto';
import { RefreshTokenGuard } from '../common/guards/refreshToken.guard';
import { GoogleOauthGuard } from './guards/google-oauth.guard';
import { MicrosoftOauthGuard } from './guards/microsoft-oauth.guard';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { ConfigService } from '@nestjs/config';
import { UpdatePasswordDto } from './dto/update.password.dto';

@Controller('v1/auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Get('email-check/:email')
  emailCheck(@Param('email') email: string) {
    return this.authService.emailCheck(email);
  }

  @Post('signup')
  signup(@Body() createAuthDto: SignupDto) {
    return this.authService.signup(createAuthDto);
  }

  @Post('signin')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Get('refresh')
  @UseGuards(RefreshTokenGuard)
  refresh(@Req() req: Request) {
    return this.authService.refreshToken(req);
  }

  @Post('verify')
  verifyEmail(@Body() verifyEmailDto: TokenDto) {
    return this.authService.verifyEmail(verifyEmailDto);
  }

  @Post('resend/verification')
  @UseGuards(AccessTokenGuard)
  resendVerification(@Req() req: Request) {
    return this.authService.resendVerification(req);
  }

  @Post('password/forgot')
  forgotPassword(@Body() emailDto: EmailDto) {
    return this.authService.forgotPassword(emailDto);
  }

  @Post('password/reset')
  resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }

  @Post('password/update')
  @UseGuards(AccessTokenGuard)
  updatePassword(
    @Body() updatePasswordDto: UpdatePasswordDto,
    @Req() req: Request,
  ) {
    return this.authService.updatePassword(updatePasswordDto, req);
  }

  @Get('google')
  @UseGuards(GoogleOauthGuard)
  async googleAuth(@Req() _req) {
    // Guard redirects
  }

  @Get('google/redirect')
  @UseGuards(GoogleOauthGuard)
  async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
    const auth = await this.authService.socialRegister(req);
    const baseUrl = this.configService.get<string>(
      'APP_URL',
      'http://localhost:3000',
    );
    const feUrl = `${baseUrl}/auth?authResponse=${JSON.stringify(auth)}`;

    res.redirect(feUrl);
  }

  @Get('microsoft')
  @UseGuards(MicrosoftOauthGuard)
  async microsoftAuth(@Req() _req) {
    // Guard redirects
  }

  @Get('microsoft/redirect')
  @UseGuards(MicrosoftOauthGuard)
  async microsoftAuthRedirect(@Req() req: Request, @Res() res: Response) {
    const auth = await this.authService.socialRegister(req);
    const baseUrl = this.configService.get<string>(
      'APP_URL',
      'http://localhost:3000',
    );
    const feUrl = `${baseUrl}/auth?authResponse=${JSON.stringify(auth)}`;

    res.redirect(feUrl);
  }
}
