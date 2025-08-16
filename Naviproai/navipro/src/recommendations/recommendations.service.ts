import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import { RoadmapService } from '../roadmap/roadmap.service';
import { VideoRecommendation } from './dto/video-recommendation.dto';

@Injectable()
export class RecommendationsService {
  private readonly logger = new Logger(RecommendationsService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly roadmapService: RoadmapService,
  ) {}

  async getWeeklyVideos(userId: string): Promise<VideoRecommendation[]> {
    const currentWeek = await this.roadmapService.getCurrentWeek(userId);
    if (!currentWeek) {
      this.logger.log(`No active week found for user ${userId}, returning dummy videos.`);
      return this.getDummyVideos();
    }

    const youtubeApiKey = this.configService.youtubeApiKey;
    if (!youtubeApiKey) {
      this.logger.warn('YOUTUBE_API_KEY not configured. Falling back to dummy videos.');
      return this.getDummyVideos();
    }

    const query = `${currentWeek.focus} tutorial for beginners`;
    this.logger.log(`Searching YouTube for: "${query}"`);

    try {
      const { got } = await import('got');
      const response = await got.get('https://www.googleapis.com/youtube/v3/search', {
        searchParams: {
          part: 'snippet',
          q: query,
          type: 'video',
          maxResults: 5,
          key: youtubeApiKey,
        },
      }).json<any>();

      return response.items.map((item: any) => ({
        title: item.snippet.title,
        url: `https://www.youtube.com/watch?v=${item.id.videoId}`,
        channel: item.snippet.channelTitle,
        thumbnail: item.snippet.thumbnails.default.url,
      }));
    } catch (error) {
      this.logger.error('Failed to fetch videos from YouTube API', error.stack);
      return this.getDummyVideos();
    }
  }

  private getDummyVideos(): VideoRecommendation[] {
    return [
      {
        title: 'Dummy Video 1: Getting Started with Your Goal',
        url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        channel: 'Helpful Channel',
        views: '1M',
        duration: '10:00',
        thumbnail: 'https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg',
      },
    ];
  }
}
