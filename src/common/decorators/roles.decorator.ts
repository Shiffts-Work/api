import { SetMetadata } from '@nestjs/common';
import { UserType } from '@prisma/client';

export const HasRoles = (...UserType: UserType[]) =>
  SetMetadata('userType', UserType);
