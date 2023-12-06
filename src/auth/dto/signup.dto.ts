import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  MinLength,
  MaxLength,
  Matches,
} from 'class-validator';
import { Match } from '../validators/match.decorator';
import { PASSWORD } from '../auth.constants';
import { ApiProperty } from '@nestjs/swagger';

export class SignupDto {
  @ApiProperty()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(20)
  @Matches(PASSWORD.REGEX)
  password: string;

  @ApiProperty()
  @IsNotEmpty()
  @Match('password')
  passwordConfirmation: string;

  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(20)
  firstName: string;

  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(20)
  lastName: string;

  @ApiProperty()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsOptional()
  address?: string;

  @ApiProperty()
  @IsNotEmpty()
  userType: any;
}
