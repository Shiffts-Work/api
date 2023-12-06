import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import Strategy from 'passport-headerapikey';
import { MongoPrismaService } from '../../prisma/mongo-prisma.service';
import { User } from '../../user/type/user.type';

@Injectable()
export class HeaderApiKeyStrategy extends PassportStrategy(
  Strategy,
  'api-key',
) {
  constructor(private readonly mongoPrismaService: MongoPrismaService) {
    super({ header: 'X-API-KEY', prefix: '' }, true, async (apiKey, done) => {
      return this.validate(apiKey, done);
    });
  }

  async validate(apiKey: string, done: (error: Error, data) => {}) {
    const dbKey = await this.mongoPrismaService.apiKey.findFirst({
      where: {
        key: apiKey,
      },
    });
    if (dbKey) {
      const enterpriseUser = await this.mongoPrismaService.user.findFirst({
        where: {
          id: dbKey.adminId,
        },
      });
      const user: User = {
        sub: enterpriseUser.id,
        email: enterpriseUser.email,
      };

      done(null, user);
    }

    done(new UnauthorizedException(), null);
  }
}
