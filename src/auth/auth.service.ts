import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from 'src/dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(dto.password);
    // save the new user in the db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }
  async signin(dto: AuthDto) {
    // Find the user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });
    // If the the user does not exist throw exception
    if (!user) {
      throw new ForbiddenException('Credentials incorrects');
    }
    // Compare passwords
    const pwMatches = await argon.verify(user.hash, dto.password);
    // If passwords dont math throw error
    if (!pwMatches) {
      throw new ForbiddenException('Credentials incorrect');
    }
    // Send back user
    delete user.hash;
    return user;
  }
}
