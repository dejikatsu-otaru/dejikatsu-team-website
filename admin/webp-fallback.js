import createEncoder from './webp-codec/webp_enc.js';
import { defaultOptions } from './webp-codec/meta.js';

// Only loaded when canvas cannot produce a metadata-free WebP (notably WebKit).
// Codec and WASM are served by this site; image pixels never leave the browser.
let encoderPromise;
export async function encodeWebp(canvas, quality) {
  if (!encoderPromise) encoderPromise = createEncoder({ noInitialRun: true });
  const encoder = await encoderPromise;
  const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
  const bytes = encoder.encode(pixels.data, pixels.width, pixels.height, { ...defaultOptions, quality: quality * 100 });
  if (!bytes) throw new Error('画像をWebPへ変換できませんでした。');
  return new Blob([bytes], { type: 'image/webp' });
}
