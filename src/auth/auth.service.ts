// @ts-nocheck
import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
  InternalServerErrorException,
  ForbiddenException,
  NotAcceptableException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
// import { MailService } from '../mail/mail.service';
import { TokenType, UserStatus, UserType } from '@prisma/client';
import { EmailDto } from './dto/email.dto';
import { ResetPasswordDto } from './dto/reset.password.dto';
import { TokenDto } from './dto/token.dto';
import { ConfigService } from '@nestjs/config';
import { TokenService } from '../token/token.service';
import { JwtPayload } from 'jwt-decode';
import { Request } from 'express';
import { PASSWORD } from './auth.constants';
import crypto from 'crypto';
import { User } from '../user/type/user.type';
import { MongoPrismaService } from '../prisma/mongo-prisma.service';
import { UpdatePasswordDto } from './dto/update.password.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    // private mailService: MailService,
    private configService: ConfigService,
    private tokenService: TokenService,
    private mongoPrismaService: MongoPrismaService,
  ) {}

  async emailCheck(email: string) {
    const user = await this.usersService.findByEmail({ email });

    if (!user) throw new NotFoundException('User not found');

    return user.firstName;
  }

  async login({ email, password }: LoginDto) {
    const user = await this.usersService.findByEmail({ email });

    if (!user) throw new NotFoundException('User not found');

    if (user.isTeam && user.status == UserStatus.INACTIVE)
      throw new ForbiddenException('User Deactivated by team admin!');

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) throw new ForbiddenException('Invalid Password');

    const tokens = await this.createTokens(user.id, email, user.userType);

    return {
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        userType: user.userType,
        isEmailVerified: user.isEmailVerified,
        status: user.status,
        isTeam: user.isTeam,
        isTeamAdmin: user.isTeamAdmin,
      },
      tokens: tokens,
    };
  }

  async createTokens(userId: string, email: string, userType: string) {
    const tokens = await this.getJwtTokens(userId, email, userType);

    await this.tokenService.createOrUpdate({
      where: {
        email_tokenType: {
          email,
          tokenType: TokenType.JWT,
        },
      },
      update: {
        token: await bcrypt.hash(tokens.refreshToken, PASSWORD.SALT),
        expiry: await this.getTokenExpiry(tokens.refreshToken),
      },
      create: {
        email,
        token: await bcrypt.hash(tokens.refreshToken, PASSWORD.SALT),
        expiry: await this.getTokenExpiry(tokens.refreshToken),
        tokenType: TokenType.JWT,
      },
    });

    return tokens;
  }

  async getTokenExpiry(token: string) {
    const decodedJwtAccessToken: JwtPayload = this.jwtService.decode(
      token,
    ) as JwtPayload;
    return new Date(decodedJwtAccessToken.exp! * 1000);
  }

  async getJwtTokens(userId: string, username: string, userType: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
          userType,
        },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: this.configService.get<string>(
            'JWT_ACCESS_TOKEN_EXPIRES_IN',
          ),
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: this.configService.get<string>(
            'JWT_REFRESH_TOKEN_EXPIRES_IN',
          ),
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(req: Request) {
    const userId = req.user['sub'];
    const token = req.user['refreshToken'];
    const user = await this.mongoPrismaService.user.findFirst({
      where: { id: userId },
    });

    if (!user) throw new NotFoundException('User not found');

    if (user.isTeam && user.status == UserStatus.INACTIVE)
      throw new ForbiddenException('User Deactivated by team admin!');

    const refreshToken = await this.tokenService.findByQuery({
      where: {
        email: user.email,
        tokenType: TokenType.JWT,
      },
    });

    if (!refreshToken) throw new ForbiddenException('Token not found');

    const isTokenValid = await bcrypt.compare(token, refreshToken.token);

    if (!isTokenValid) throw new ForbiddenException('Invalid Token');

    if (new Date(refreshToken.expiry) < new Date())
      throw new UnauthorizedException('Refresh Token Expired');

    const tokens = await this.createTokens(
      user.id,
      refreshToken.email,
      user.userType,
    );

    return {
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        userType: user.userType,
        isEmailVerified: user.isEmailVerified,
        status: user.status,
        isTeam: user.isTeam,
        isTeamAdmin: user.isTeamAdmin,
      },
      accessToken: tokens.accessToken,
    };
  }

  async signup(signupData: SignupDto) {
    const { email, password, userType, address, firstName, lastName } =
      signupData;
    const dbUser = await this.usersService.findByEmail({ email });

    if (dbUser) throw new ForbiddenException('User already registred');

    const hashedPassword = await bcrypt.hash(password, PASSWORD.SALT);

    const newUser = {
      email,
      userType,
      password: hashedPassword,
      address,
      firstName,
      lastName,
      isTeam: false,
      adminId: '',
    };

    try {
      const user = await this.usersService.create(newUser);

      await this.createEmailVerificationToken(email, firstName);

      const tokens = await this.createTokens(user.id, email, user.userType);

      return {
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          userType: user.userType,
          isEmailVerified: user.isEmailVerified,
          status: user.status,
          isTeam: user.isTeam,
          isTeamAdmin: user.isTeamAdmin,
        },
        tokens: tokens,
      };
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  async socialRegister(req: Request) {
    const user: User = req.user;
    if (!user) throw new ForbiddenException('Authentication Failed');
    let dbUser = await this.usersService.findByEmail({ email: user.email });

    if (!dbUser) {
      const newUser = {
        email: user.email,
        password: '',
        address: '',
        userType: UserType.EMPLOYEE,
        socialProvider: user.provider,
        socialId: user.providerId,
        firstName: user.firstName,
        lastName: user.lastName,
        isEmailVerified: true,
        status: UserStatus.ACTIVE,
        isTeam: false,
        adminId: '',
      };

      dbUser = await this.usersService.create(newUser);
    } else {
      await this.usersService.update(dbUser.id, {
        socialProvider: user.provider,
        socialId: user.providerId,
        isEmailVerified: true,
        status: UserStatus.ACTIVE,
      });
    }

    const tokens = await this.createTokens(
      dbUser.id,
      dbUser.email,
      dbUser.userType,
    );

    return {
      user: {
        id: dbUser.id,
        firstName: dbUser.firstName,
        lastName: dbUser.lastName,
        userType: dbUser.userType,
        isEmailVerified: dbUser.isEmailVerified,
        status: dbUser.status,
        isTeam: dbUser.isTeam,
        isTeamAdmin: dbUser.isTeamAdmin,
      },
      tokens: tokens,
    };
  }

  async resendVerification(req: Request) {
    const user: User = req.user;
    const dbUser = await this.mongoPrismaService.user.findFirst({
      where: { id: user.sub },
    });

    if (dbUser.isEmailVerified)
      throw new NotAcceptableException('Email already verified!');

    await this.tokenService.delete({
      email: dbUser.email,
      tokenType: TokenType.VERIFY_EMAIL,
    });

    return await this.createEmailVerificationToken(
      dbUser.email,
      dbUser.firstName,
    );
  }

  async createEmailVerificationToken(email: string, name: string) {
    const { token, expiry } = await this.createTokenAndExpiry();

    await this.tokenService.create({
      email,
      expiry,
      token,
      tokenType: TokenType.VERIFY_EMAIL,
    });

    // return await this.mailService.sendVerificationEmail({ email, token, name });
  }

  async verifyEmail(tokenDto: TokenDto) {
    const { token } = tokenDto;

    const userToken = await this.tokenService.findByQuery({
      where: {
        token,
        tokenType: TokenType.VERIFY_EMAIL,
      },
    });

    if (!userToken) throw new UnauthorizedException('Invaild Token');

    const user = await this.usersService.findByEmail({
      email: userToken.email,
    });

    if (!user) throw new NotFoundException('User Not Found');

    if (new Date(userToken.expiry) < new Date())
      throw new UnauthorizedException('Token Expired');

    await this.usersService.update(user.id, {
      status: UserStatus.ACTIVE,
      isEmailVerified: true,
    });

    return await this.tokenService.delete({
      id: userToken.id,
      tokenType: TokenType.VERIFY_EMAIL,
    });
  }

  async forgotPassword(emailDto: EmailDto) {
    const { email } = emailDto;
    const dbUser = await this.usersService.findByEmail({ email });

    if (!dbUser) throw new NotFoundException('User Not found');

    await this.tokenService.delete({
      email,
      tokenType: TokenType.PASSWORD_RECOVERY,
    });

    const { token, expiry } = await this.createTokenAndExpiry();

    await this.tokenService.create({
      email,
      expiry,
      token,
      tokenType: TokenType.PASSWORD_RECOVERY,
    });

    // return await this.mailService.sendForgotPasswordEmail({ email, token });
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { token, password } = resetPasswordDto;

    const userToken = await this.tokenService.findByQuery({
      where: {
        token,
        tokenType: TokenType.PASSWORD_RECOVERY,
      },
    });

    if (!userToken) throw new UnauthorizedException('Invaild Token');

    if (new Date(userToken.expiry) < new Date())
      throw new UnauthorizedException('Token Expired');

    const user = await this.usersService.findByEmail({
      email: userToken.email,
    });

    if (!user) throw new NotFoundException('User not found');

    const hashedPassword = await bcrypt.hash(password, PASSWORD.SALT);
    const updateUser = { password: hashedPassword };

    return await this.usersService.update(user.id, updateUser);
  }

  async updatePassword(updatePasswordDto: UpdatePasswordDto, req: Request) {
    const { currentPassword, newPassword } = updatePasswordDto;
    const user: User = req.user;
    const dbUser = await this.mongoPrismaService.user.findFirst({
      where: { id: user.sub },
    });
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      dbUser.password,
    );

    if (!isPasswordValid)
      throw new ForbiddenException('Invalid Current Password!');

    const hashedPassword = await bcrypt.hash(newPassword, PASSWORD.SALT);

    return await this.usersService.update(dbUser.id, {
      password: hashedPassword,
    });
  }

  async createTokenAndExpiry() {
    const token = crypto.randomUUID();
    const expiry = new Date();

    expiry.setUTCDate(expiry.getUTCDate() + 1);

    return {
      token,
      expiry,
    };
  }

  async getUserFromAuthenticationToken(token: string) {
    const payload: JwtPayload = this.jwtService.verify(token, {
      secret: this.configService.get('JWT_ACCESS_SECRET'),
    });

    const userId = payload.sub;

    if (!userId) throw new UnauthorizedException('Invalid Token!');

    return await this.mongoPrismaService.user.findFirst({
      where: { id: userId },
    });
  }
}
