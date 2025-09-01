// This file is a manual mock for the 'got' library.
// Jest will automatically use this file instead of the actual 'got' module.

const jsonMock = jest.fn().mockResolvedValue({});

const gotInstance = {
  get: jest.fn(() => ({ json: jsonMock })),
  post: jest.fn(() => ({ json: jsonMock })),
  patch: jest.fn(() => ({ json: jsonMock })),
};

const got = {
  extend: jest.fn(() => gotInstance),
  get: jest.fn(() => ({ json: jsonMock })),
  post: jest.fn(() => ({ json: jsonMock })),
  patch: jest.fn(() => ({ json: jsonMock })),
};

export default got;
