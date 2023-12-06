import { HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import { MongoPrismaService } from '../prisma/mongo-prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Request } from 'express';
import { UserStatus, UserType } from '@prisma/client';

// import { MailService } from '../mail/mail.service';
import { User } from '../user/type/user.type';
import {
  PaginateFunction,
  paginator,
} from '../common/interfaces/paginate.interface';
import { exclude } from '../common/helpers/user.helper';
import { EventEmitter2 } from '@nestjs/event-emitter';

const paginate: PaginateFunction = paginator({ skip: 0, take: 10 });
@Injectable()
export class UserService {
  constructor(
    private readonly mongoPrismaService: MongoPrismaService,
    // private mailService: MailService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async findAll(params: {
    skip?: number;
    take?: number;
    orderBy?: string;
    filterDate: string;
    req: Request;
  }) {
    const { skip, take, orderBy, req } = params;
    const user: User = req.user;
    const adminUser = await this.mongoPrismaService.user.findFirst({
      where: {
        id: user.sub,
      },
    });

    switch (adminUser.userType) {
      case UserType.ADMIN:
        return this.getAllUsers(skip, take, orderBy);
      default:
        return { data: [], meta: { total: 0 } };
    }
  }

  async getAllUsers(skip, take, orderBy) {
    return await paginate(this.mongoPrismaService.user, {
      skip,
      take,
      orderBy,
    });
  }

  async findOne(id: string) {
    const user = await this.mongoPrismaService.user.findUnique({
      where: {
        id,
      },
    });

    return exclude(user, ['password']);
  }

  async accountDetails(req: Request) {
    const user: User = req.user;

    return exclude(
      await this.mongoPrismaService.user.findFirst({
        where: {
          id: user.sub,
        },
      }),
      ['password'],
    );
  }

  findByEmail({ email }: Partial<{ email: string }>) {
    return this.mongoPrismaService.user.findFirst({
      where: {
        email,
      },
    });
  }

  create(userDetails: CreateUserDto) {
    return this.mongoPrismaService.user.create({ data: userDetails });
  }

  async update(id: string, userDetails: UpdateUserDto) {
    const user = await this.mongoPrismaService.user.findUnique({
      where: {
        id,
      },
    });

    if (!user) throw new NotFoundException('User Not Found');

    if (user.isEmailVerified && userDetails.hasOwnProperty('isEmailVerified')) {
      delete userDetails.isEmailVerified;
    }

    if (
      user.status === UserStatus.ACTIVE &&
      userDetails.hasOwnProperty('status')
    ) {
      delete userDetails.status;
    }

    return this.mongoPrismaService.user.update({
      where: {
        id,
      },
      data: userDetails,
    });
  }

  async delete(id: string) {
    try {
      await this.mongoPrismaService.user.delete({
        where: {
          id,
        },
      });

      return HttpStatus.ACCEPTED;
    } catch (error) {
      return HttpStatus.EXPECTATION_FAILED;
    }
  }
}
