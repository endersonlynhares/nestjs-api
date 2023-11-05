import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";

@Injectable()
export class AuthService {

  constructor(private prismaService: PrismaService) {
  }

  async signup(dto: AuthDto) {
    //generate the password hash
    const hash = await argon.hash(dto.password);

    //save the new user in the database
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          hash
        }
      });

      delete user.hash;

      //return the saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === "P2002") {
          throw new ForbiddenException("Credentials taken");
        }
      }

      throw error;
    }
  }

  signin() {
    return {
      msg: "I have signed in"
    };
  }
}


// 1:12:42 - video parou aqui!!