import { jest } from '@jest/globals';

// This object simulates the chainable .json() method.
// We export it so that tests can control its behavior (e.g., mockResolvedValue).
export const mockJsonResponse = jest.fn<() => Promise<any>>().mockResolvedValue(undefined);

// This object simulates the response from a got call, which has the .json() method.
const mockRequest = {
  json: mockJsonResponse,
};

// This is the mock for the 'got' function itself.
// We can spy on .post, .get, etc.
const got = {
  post: jest.fn().mockReturnValue(mockRequest),
  get: jest.fn().mockReturnValue(mockRequest),
  // Add other methods like put, delete if you use them
};

// Since 'got' is an ESM module with a default export, we must mock it the same way.
// This is what will be imported when your application code calls `(await import('got')).default`.
export default got;