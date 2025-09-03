// config.validation.js
import * as Joi from 'joi';

export const configValidationSchema = Joi.object({
  JWT_SECRET: Joi.string().min(32).required(),
  DATABASE_URL: Joi.string().uri().required(),
  PORT: Joi.number().default(3000),
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  AI_AGENT_URL: Joi.string().uri().required(),
});
