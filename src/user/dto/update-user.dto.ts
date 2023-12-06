import { IsOptional, MinLength, MaxLength, Matches } from 'class-validator';
import { SocialProvider, UserStatus } from '@prisma/client';
import { PASSWORD } from '../../auth/auth.constants';

export class UpdateUserDto {
  @IsOptional()
  @MaxLength(20)
  firstName?: string;

  @IsOptional()
  @MaxLength(20)
  lastName?: string;

  @IsOptional()
  status?: UserStatus;

  @IsOptional()
  @MinLength(8)
  @MaxLength(20)
  @Matches(PASSWORD.REGEX)
  password?: string;

  @IsOptional()
  isEmailVerified?: boolean;

  @IsOptional()
  isIdVerified?: boolean;

  @IsOptional()
  address?: string;

  @IsOptional()
  socialProvider?: SocialProvider;

  @IsOptional()
  socialId?: string;

  @IsOptional()
  isTeamAdmin?: boolean;

  @IsOptional()
  companyName?: string;
}
