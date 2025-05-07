import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { read } from 'fs';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const logger = new Logger('Auth-MS');

  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3004);

  logger.log('🚀 Application is running on: http://localhost:3004'); 

}
bootstrap();
