import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { RoadmapService } from '../roadmap/roadmap.service';

@Injectable()
export class RecommendationsService {
  private readonly logger = new Logger(RecommendationsService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly roadmapService: RoadmapService,
  ) {}

  async getWeeklyVideos(userId: string): Promise<any> {
    const youtubeApiKey = this.configService.youtubeApiKey;
    if (!youtubeApiKey) {
      this.logger.warn('YouTube API key not configured. Skipping video recommendations.');
      return { videos: [] };
    }

    const currentWeek = await this.roadmapService.getCurrentWeek(userId);
    if (!currentWeek) {
      return { videos: [] }; // No current week to base recommendations on
    }

    const searchQuery = encodeURIComponent(
      `tutorial for ${currentWeek.focus}`,
    );
    const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${searchQuery}&type=video&key=${youtubeApiKey}&maxResults=5`;

    try {
      const { got } = await import('got');
      const response = await got.get(url).json<any>();

      const videos = response.items.map((item: any) => ({
        id: item.id.videoId,
        title: item.snippet.title,
        thumbnail: item.snippet.thumbnails.default.url,
      }));

      return { videos };
    } catch (error) {
      this.logger.error(
        'Failed to fetch videos from YouTube API',
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException(
        'Could not fetch video recommendations.',
      );
    }
  }
}