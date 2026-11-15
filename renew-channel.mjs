import { readFile, writeFile, rename } from 'node:fs/promises';
import { createPrivateKey, createPublicKey, createHash, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export async function renew(envelope, jwk, download, now = Date.now()) {
  const key = createPrivateKey({ key: jwk, format: 'jwk' });
  const publicKey = createPublicKey(key);
  const bytes = Buffer.from(envelope.payload, 'base64');
  if (!verify('RSA-SHA256', bytes, publicKey, Buffer.from(envelope.signature, 'base64'))) {
    throw new Error('Existing channel signature does not match the release key.');
  }
  const m = JSON.parse(bytes.toString('utf8'));
  if (m.schema !== 1 || m.product !== 'StayReviewAssistant' || m.channel !== 'stable' ||
      !/^\d+\.\d+\.\d+\.\d+$/.test(m.version) || !Number.isSafeInteger(m.sequence) || m.sequence < 1 ||
      !Number.isSafeInteger(m.size) || m.size < 1 || m.size > 25 * 1024 * 1024 ||
      !/^[a-f0-9]{64}$/.test(m.sha256) || typeof m.notes !== 'string' || m.notes.length > 3000) {
    throw new Error('Invalid release metadata.');
  }
  const expected = `https://github.com/seon0030-bot/stay-review-assistant-updates/releases/download/updates/StayReviewAssistant-update-${m.version}.zip`;
  if (m.packageUrl !== expected) throw new Error('Unexpected package destination.');
  const packageBytes = await download(m.packageUrl, m.size);
  if (packageBytes.length !== m.size || createHash('sha256').update(packageBytes).digest('hex') !== m.sha256) {
    throw new Error('Published package is unavailable or has changed. Channel was not renewed.');
  }
  const sequence = Math.max(now, m.sequence + 1);
  if (!Number.isSafeInteger(sequence)) throw new Error('Invalid sequence.');
  const next = { ...m, sequence, publishedUtc: new Date(now).toISOString(), expiresUtc: new Date(now + 30 * 86400000).toISOString() };
  const payload = Buffer.from(JSON.stringify(next));
  return { payload: payload.toString('base64'), signature: sign('RSA-SHA256', payload, key).toString('base64') };
}

async function download(url, expectedSize) {
  const signal = AbortSignal.timeout(60000);
  for (let redirects = 0; redirects < 5; redirects++) {
    const u = new URL(url);
    if (u.protocol !== 'https:' || u.username || u.password || u.port ||
        !['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(u.hostname)) {
      throw new Error('Unexpected download redirect.');
    }
    const response = await fetch(u, { redirect: 'manual', signal });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      await response.body?.cancel();
      if (!location) throw new Error('Missing redirect.');
      url = new URL(location, u).href;
      continue;
    }
    if (!response.ok) throw new Error(`Package download failed: ${response.status}`);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > expectedSize) throw new Error('Package is too large.');
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }
  throw new Error('Too many redirects.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const secret = process.env.RELEASE_SIGNING_JWK;
  delete process.env.RELEASE_SIGNING_JWK;
  if (!secret) throw new Error('Release signing secret is not configured.');
  const envelope = JSON.parse(await readFile('channel/latest.json', 'utf8'));
  const next = await renew(envelope, JSON.parse(secret), download);
  await writeFile('channel/latest.json.next', JSON.stringify(next) + '\n');
  await rename('channel/latest.json.next', 'channel/latest.json');
  console.log('Published package verified; signed channel validity renewed for 30 days.');
}
