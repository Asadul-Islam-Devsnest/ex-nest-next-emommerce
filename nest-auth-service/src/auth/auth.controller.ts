import { Controller, Post, Body, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Body() body: { email: string; password: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateUser(body.email, body.password);
    const tokens = await this.authService.login(user);

    res.cookie('refresh_token', tokens.refreshToken, {
      httpOnly: true,
      path: '/auth/refresh',
    });

    return { accessToken: tokens.accessToken };
  }

  //   @Post('refresh')
  //   async refresh(@Body('token') token: string) {
  //     // verify refresh token
  //   }
}
