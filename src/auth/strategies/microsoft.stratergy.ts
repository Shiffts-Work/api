import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { SocialProvider } from '@prisma/client';
import { Strategy } from 'passport-microsoft';
import { User } from 'src/user/type/user.type';

@Injectable()
export class MicrosoftStratergy extends PassportStrategy(
  Strategy,
  'microsoft',
) {
  constructor() {
    super({
      clientID: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL: process.env.MICROSOFT_CALLBACK_URL,
      scope: ['openid', 'profile', 'email', 'user.read'],
      // Microsoft specific options
      // [Optional] The tenant for the application. Defaults to 'common'.
      // Used to construct the authorizationURL and tokenURL
      tenant: 'common',

      // [Optional] The authorization URL. Defaults to `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`
      authorizationURL:
        'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',

      // [Optional] The token URL. Defaults to `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`
      tokenURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    });
  }

  async validate(accessToken, refreshToken, profile, done) {
    const { id, name, emails } = profile;

    const user: User = {
      provider: SocialProvider.MICROSOFT,
      providerId: id,
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
    };

    done(null, user);
  }
}
