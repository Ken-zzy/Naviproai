import * as Joi from 'joi';

export const configValidationSchema = Joi.object({
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRES_IN: Joi.string().default('1d').required(),
  DATABASE_URL: Joi.string().uri().required(),
  AI_AGENT_URL: Joi.string().uri().required(),
  AI_AGENT_KEY: Joi.string().required(),
  GOOGLE_CLIENT_ID: Joi.string().required(),
  GOOGLE_CLIENT_SECRET: Joi.string().required(),
  GOOGLE_CALLBACK_URL: Joi.string().uri().required(),
  FRONTEND_URL: Joi.string().required(),
  FRONTEND_DASHBOARD_URL: Joi.string().uri().required(),
  DASHBOARD_URL: Joi.string().uri().required(),
  BACKEND_URL: Joi.string().uri().required(),
  EMAIL_HOST: Joi.string().required(),
  EMAIL_PORT: Joi.number().required(),
  EMAIL_SECURE: Joi.boolean().required(),
  EMAIL_USER: Joi.string().email().required(),
  EMAIL_PASS: Joi.string().required(),
  EMAIL_FROM: Joi.string().required(),
  YOUTUBE_API_KEY: Joi.string().optional(),
  ONESIGNAL_APP_ID: Joi.string().optional(),
  ONESIGNAL_API_KEY: Joi.string().optional(),
  THROTTLE_TTL: Joi.number().default(60),
  THROTTLE_LIMIT: Joi.number().default(20),
  PORT: Joi.number().default(3000),
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
});
