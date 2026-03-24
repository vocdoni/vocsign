import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookup } from 'node:dns/promises';

const PRIVATE_RANGES = [
  { prefix: '127.', label: 'loopback' },
  { prefix: '10.', label: 'private' },
  { prefix: '192.168.', label: 'private' },
  { prefix: '169.254.', label: 'link-local' },
  { prefix: '0.', label: 'unspecified' },
  { prefix: '::1', label: 'loopback' },
  { prefix: 'fc', label: 'private' },
  { prefix: 'fd', label: 'private' },
  { prefix: 'fe80:', label: 'link-local' },
];

function isPrivateIP(ip: string): boolean {
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return PRIVATE_RANGES.some((r) => ip.startsWith(r.prefix));
}

export interface SafeFetchOpts {
  method?: 'GET' | 'POST';
  body?: Buffer;
  contentType?: string;
  timeoutMs?: number;
  maxBytes?: number;
  /** Only for testing — allows requests to private IPs. */
  allowLocalhost?: boolean;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

export async function safeFetch(
  urlStr: string,
  opts: SafeFetchOpts = {}
): Promise<Buffer> {
  const url = new URL(urlStr);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;

  let ip: string;
  if (url.hostname.startsWith('[') || url.hostname === '::1') {
    ip = url.hostname.replace(/[[\]]/g, '');
  } else {
    try {
      const resolved = await lookup(url.hostname);
      ip = resolved.address;
    } catch {
      throw new Error(`DNS resolution failed for ${url.hostname}`);
    }
  }

  if (!opts.allowLocalhost && isPrivateIP(ip)) {
    throw new Error(`Request to private/internal IP blocked: ${ip}`);
  }

  const reqFn = url.protocol === 'https:' ? httpsRequest : httpRequest;

  return new Promise<Buffer>((resolve, reject) => {
    const req = reqFn(
      url,
      {
        method: opts.method ?? 'GET',
        timeout: timeoutMs,
        headers: opts.contentType
          ? { 'Content-Type': opts.contentType }
          : undefined,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > maxBytes) {
            req.destroy();
            reject(new Error(`Response size exceeds limit of ${maxBytes} bytes`));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 400) {
            reject(new Error(`HTTP ${res.statusCode} from ${url.hostname}`));
            return;
          }
          resolve(Buffer.concat(chunks));
        });

        res.on('error', reject);
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timed out after ${timeoutMs}ms`));
    });

    req.on('error', reject);

    if (opts.body) {
      req.write(opts.body);
    }
    req.end();
  });
}
