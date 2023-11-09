import { Controller, Get, Post, UseGuards } from "@nestjs/common";
import { JwtGuard } from "../auth/guards";
import { GetUser } from "../auth/decorators";
import { User } from "@prisma/client";

@UseGuards(JwtGuard)
@Controller("users")
export class UserController {
  constructor() {
  }

  @Get("")
  getUser(@GetUser() user: User) {
    return user;
  }

  @Post("user")
  addUser() {

  }
}
