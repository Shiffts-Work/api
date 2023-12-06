import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { useContainer } from 'class-validator';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { rawBody: true });
  const configService = app.get(ConfigService);

  const baseUrl =
    configService
      .get<string>('APP_URL', 'https://localhost:3000')
      ?.split(',') || [];
  const baseMode = configService.get<string>('BASE_MODE');

  app.enableCors({
    origin:
      baseMode === 'dev' || baseMode === 'stg'
        ? [
            `http://localhost:3000`,
            `http://127.0.0.1:3000`,
            `http://0.0.0.0:3000`,
            ...baseUrl,
          ]
        : baseUrl,
    credentials: true,
    exposedHeaders: ['Content-Disposition'],
  });

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
    }),
  );

  useContainer(app.select(AppModule), { fallbackOnErrors: true });

  app.enableShutdownHooks();

  const config = new DocumentBuilder()
    .addApiKey({ type: 'apiKey', name: 'X-API-KEY', in: 'header' }, 'X-API-KEY')
    .addBearerAuth()
    .setTitle('Shiffts API')
    .setDescription(
      'You can find documentation for all endpoints on Shiffts website.',
    )
    .setVersion('0.0.1')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
  const host = configService.get<string>('HOST', 'localhost');
  const port = configService.get<number>('PORT', 3333);

  await app.listen(port, host, () => {
    console.info(`API server is running on http://${host}:${port}`);
  });
}
bootstrap();
