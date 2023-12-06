import {
  Controller,
  Get,
  Body,
  Patch,
  Param,
  UseGuards,
  Req,
  Post,
  Query,
} from '@nestjs/common';
import { Request } from 'express';
import { UserService } from './user.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { ApiBearerAuth } from '@nestjs/swagger';

@Controller('v1/user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @ApiBearerAuth()
  @UseGuards(AccessTokenGuard)
  @Get()
  findAll(
    @Query()
    query: { skip: number; take: number; orderBy: string; filterDate: string },
    @Req() req: Request,
  ) {
    return this.userService.findAll({
      skip: Number(query.skip),
      take: Number(query.take),
      orderBy: query.orderBy,
      filterDate: query.filterDate,
      req,
    });
  }

  @ApiBearerAuth()
  @UseGuards(AccessTokenGuard)
  @Get('account-details')
  accountDetails(@Req() req: Request) {
    return this.userService.accountDetails(req);
  }

  @UseGuards(AccessTokenGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.userService.findOne(id);
  }

  @ApiBearerAuth()
  @UseGuards(AccessTokenGuard)
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(id, updateUserDto);
  }

  @ApiBearerAuth()
  @UseGuards(AccessTokenGuard)
  @Post('delete/:id')
  delete(@Param('id') id: string) {
    return this.userService.delete(id);
  }
}
