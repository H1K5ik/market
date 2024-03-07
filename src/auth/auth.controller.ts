import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('local/singup')
  singuplocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.singuplocal(dto);
  }

  @Post('local/singin')
  singinlocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.singinlocal(dto);
  }
  @Post('logout')
  logout() {
    return this.authService.logout();
  }
  @Post('refresh')
  refreshTokens() {
    return this.authService.refreshTokens();
  }
}
