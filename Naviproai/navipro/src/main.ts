import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from './config/config.service';

import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.port || 3000;

        app.enableCors({
    origin: '*',
    credentials: true,
  });
  app.use(
    helmet({
      xPoweredBy: false, // Explicitly disable x-powered-by
      xFrameOptions: false, // Disable the old x-frame-options header
      contentSecurityPolicy: false, // Disable CSP as requested by the user report
    }),
  );
  app.use(compression());
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  await app.listen(port);
  Logger.log(`🚀 Application is running on: http://localhost:${port}`);
}
bootstrap();
