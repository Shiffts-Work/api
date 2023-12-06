import { SocialProvider } from '@prisma/client';

export type User = {
  provider?: SocialProvider;
  providerId?: string;
  userType?: string;
  email?: string;
  sub?: string;
  firstName?: string;
  lastName?: string;
  enterpriseId?: string;
};
