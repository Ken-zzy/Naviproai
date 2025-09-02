import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AiController } from './ai.controller';
import { AiService } from './ai.service';
import { ConfigModule } from '../config/config.module';
import { RoadmapModule } from '../roadmap/roadmap.module';

import { UserModule } from '../user/user.module';
import { ChatHistory, ChatHistorySchema } from './schemas/chat-history.schema';

@Module({
  imports: [
    ConfigModule, RoadmapModule, UserModule,
    MongooseModule.forFeature([{ name: ChatHistory.name, schema: ChatHistorySchema }]),
  ],
  controllers: [AiController],
  providers: [AiService],
})
export class AiModule {}
