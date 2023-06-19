import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signUp(payload: AuthDto) {
    const hashedPwd = await argon.hash(payload.password);
    try {
      const newUser = await this.prisma.user.create({
        data: { email: payload.email, hash: hashedPwd },
      });
      // hide password hash from response
      delete newUser.hash;
      return { message: 'success', user: newUser };
    } catch (e) {
      if (e instanceof PrismaClientKnownRequestError) {
        if (e.code === 'P2002') {
          throw new ForbiddenException('credentials unavailable');
        }
      }
      throw e;
    }
  }

  async login(payload: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: payload.email },
    });
    if (!user) throw new ForbiddenException('Incorrect credentials');
    const passwordMatch = await argon.verify(user.hash, payload.password);
    if (!passwordMatch) throw new ForbiddenException('Incorrect password');
    delete user.hash;
    return user;
  }
}
