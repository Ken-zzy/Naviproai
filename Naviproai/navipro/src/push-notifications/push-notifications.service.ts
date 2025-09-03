import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '../config/config.service';

interface PushPayload {
  title: string;
  body: string;
}

@Injectable()
export class PushNotificationsService {
  private readonly logger = new Logger(PushNotificationsService.name);
  private readonly oneSignalAppId: string | undefined;
  private readonly oneSignalApiKey: string | undefined;

  constructor(private readonly configService: ConfigService) {
    this.oneSignalAppId = this.configService.oneSignalAppId;
    this.oneSignalApiKey = this.configService.oneSignalApiKey;
  }

  async send(tokens: string[], payload: PushPayload): Promise<void> {
    if (!this.oneSignalAppId || !this.oneSignalApiKey) {
      this.logger.warn('OneSignal not configured, skipping push notification.');
      return;
    }

    try {
      const { got } = await import('got');
      await got.post('https://onesignal.com/api/v1/notifications', {
        headers: {
          Authorization: `Basic ${this.oneSignalApiKey}`,
        },
        json: {
          app_id: this.oneSignalAppId,
          include_player_ids: tokens,
          headings: { en: payload.title },
          contents: { en: payload.body },
        },
      });
      this.logger.log(
        `Successfully sent push notification to ${tokens.length} devices.`,
      );
    } catch (error) {
      this.logger.error(
        'Failed to send push notification via OneSignal',
        error instanceof Error ? error.stack : String(error),
      );
    }
  }
}
