import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import { ConfigService } from './config/config.service';
import { ValidationPipe } from '@nestjs/common';
import * as compression from 'compression';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Set global prefix for all routes
  app.setGlobalPrefix('api');

  // Use Helmet for security-related HTTP headers
  app.use(helmet());

  // Use compression to reduce response size
  app.use(compression());

  // Enable CORS with a specific origin for production
  app.enableCors({
    origin: configService.frontendUrl,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  // Add global validation pipe to ensure all incoming data is validated
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true, // Strip away properties that do not have any decorators
    forbidNonWhitelisted: true, // Throw an error if non-whitelisted values are provided
  }));

  // Enable graceful shutdown hooks
  app.enableShutdownHooks();

  await app.listen(configService.port || 3000);
}
bootstrap();