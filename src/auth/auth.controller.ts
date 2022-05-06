import { Body, Controller, Post } from '@nestjs/common';
import { AuthDto } from 'src/dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto) {
    // console.log(dto.email);
    return this.authService.signup(dto);
  }

  @Post('signin')
  signin() {
    return this.authService.signin();
  }
}
