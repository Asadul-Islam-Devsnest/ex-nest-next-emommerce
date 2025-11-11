import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../users/user.service';
import * as bcrypt from 'bcrypt';

export interface JwtUser {
  id: number;
  email: string;
}

export interface JwtPayload {
  sub: number;
  email: string;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UserService,
    private readonly jwt: JwtService,
  ) {}

  async validateUser(email: string, pass: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new UnauthorizedException('User not found');

    // Explicitly convert user.password to a string just in case
    const isMatch = await bcrypt.compare(pass, user.password);

    if (!isMatch) throw new UnauthorizedException('Invalid credentials');

    const { password, ...result } = user;
    return result;
  }

  async login(user: JwtUser): Promise<TokenResponse> {
    const payload: JwtPayload = { email: user.email, sub: user.id };
    const accessToken = await this.jwt.signAsync(payload, { expiresIn: '15m' });
    const refreshToken = await this.jwt.signAsync(payload, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  }
}
