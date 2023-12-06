import {
  IsOptional,
  IsNotEmpty,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { SocialProvider, UserStatus, UserType } from '@prisma/client';
import { PASSWORD } from '../../auth/auth.constants';

export class CreateUserDto {
  @IsNotEmpty()
  email: string;

  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(20)
  @Matches(PASSWORD.REGEX)
  password: string;

  @IsOptional()
  @MaxLength(20)
  firstName: string;

  @IsOptional()
  @MaxLength(20)
  lastName: string;

  @IsOptional()
  status?: UserStatus;

  @IsOptional()
  userType: UserType;

  @IsOptional()
  address: string;

  @IsOptional()
  socialProvider?: SocialProvider;

  @IsOptional()
  socialId?: string;
}
