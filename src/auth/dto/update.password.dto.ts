import { IsNotEmpty, MinLength, MaxLength, Matches } from 'class-validator';
import { Match } from '../validators/match.decorator';

export class UpdatePasswordDto {
  @IsNotEmpty()
  currentPassword: string;

  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(20)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})/)
  newPassword: string;

  @IsNotEmpty()
  @Match('newPassword')
  newPasswordConfirmation: string;
}
