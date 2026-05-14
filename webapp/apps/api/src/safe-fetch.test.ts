import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { safeFetch } from './safe-fetch.js';

describe('safeFetch', () => {
  it('blocks requests to localhost', async () => {
    await expect(safeFetch('http://127.0.0.1/test')).rejects.toThrow('blocked');
  });

  it('blocks requests to private 10.x range', async () => {
    await expect(safeFetch('http://10.0.0.1/test')).rejects.toThrow('blocked');
  });

  it('blocks requests to private 172.16.x range', async () => {
    await expect(safeFetch('http://172.16.0.1/test')).rejects.toThrow('blocked');
  });

  it('blocks requests to private 192.168.x range', async () => {
    await expect(safeFetch('http://192.168.1.1/test')).rejects.toThrow('blocked');
  });

  it('blocks requests to IPv6 loopback', async () => {
    await expect(safeFetch('http://[::1]/test')).rejects.toThrow('blocked');
  });

  it('blocks requests to link-local', async () => {
    await expect(safeFetch('http://169.254.1.1/test')).rejects.toThrow('blocked');
  });

  it('enforces response size limit', async () => {
    const server = http.createServer((_, res) => {
      res.writeHead(200);
      res.end(Buffer.alloc(2 * 1024 * 1024, 'x'));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      await expect(
        safeFetch(`http://127.0.0.1:${port}/test`, {
          maxBytes: 1 * 1024 * 1024,
          allowLocalhost: true,
        })
      ).rejects.toThrow('size');
    } finally {
      server.close();
    }
  });

  it('succeeds for valid requests (via allowLocalhost)', async () => {
    const server = http.createServer((_, res) => {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      res.end(Buffer.from('hello'));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const result = await safeFetch(`http://127.0.0.1:${port}/test`, {
        allowLocalhost: true,
      });
      expect(result).toBeInstanceOf(Buffer);
      expect(result.toString()).toBe('hello');
    } finally {
      server.close();
    }
  });
});
