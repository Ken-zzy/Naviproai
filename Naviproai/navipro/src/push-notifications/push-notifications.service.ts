import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '../config/config.service';

@Injectable()
export class PushNotificationsService {
  private readonly logger = new Logger(PushNotificationsService.name);
  private readonly oneSignalAppId: string;
  private readonly oneSignalApiKey: string;

  constructor(private readonly configService: ConfigService) {
    // You would add ONESIGNAL_APP_ID and ONESIGNAL_API_KEY to your .env and config files
    this.oneSignalAppId = this.configService.oneSignalAppId;
    this.oneSignalApiKey = this.configService.oneSignalApiKey;
  }

  async send(
    tokens: string[],
    payload: { title: string; body: string },
  ): Promise<void> {
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
          include_player_ids: tokens, // Your user's pushTokens are OneSignal Player IDs
          headings: { en: payload.title },
          contents: { en: payload.body },
        },
      });
      this.logger.log(`Successfully sent push notification to ${tokens.length} devices.`);
    } catch (error) {
      this.logger.error('Failed to send push notification via OneSignal', error.stack);
    }
  }
}