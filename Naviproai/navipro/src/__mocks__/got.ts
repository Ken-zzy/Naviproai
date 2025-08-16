// This file is a manual mock for the 'got' library.
// Jest will automatically use this file instead of the actual 'got' module.
export const got = {
  post: jest.fn(),
};