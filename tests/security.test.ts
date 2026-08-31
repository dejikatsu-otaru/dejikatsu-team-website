import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  fakePasswordSalt,
  type Env,
  limitedRequestBytes,
  PASSWORD_ITERATIONS,
  protectVerifier,
  renderBody,
  safeActionUrl,
  validateClientCredential,
  verifyProtectedVerifier,
  webpDimensions,
} from "../functions/lib/cms";

const ascii = (value: string) => [...value].map((character) => character.charCodeAt(0));

function riff(chunks: Array<{ type: string; data: number[] }>): Uint8Array {
  const payload = chunks.flatMap(({ type, data }) => [
    ...ascii(type),
    data.length & 0xff, (data.length >>> 8) & 0xff, (data.length >>> 16) & 0xff, (data.length >>> 24) & 0xff,
    ...data,
    ...(data.length % 2 ? [0] : []),
  ]);
  const size = payload.length + 4;
  return new Uint8Array([
    ...ascii("RIFF"), size & 0xff, (size >>> 8) & 0xff, (size >>> 16) & 0xff, (size >>> 24) & 0xff,
    ...ascii("WEBP"), ...payload,
  ]);
}

function vp8(width: number, height: number): number[] {
  return [0, 0, 0, 0x9d, 0x01, 0x2a, width & 0xff, (width >>> 8) & 0x3f, height & 0xff, (height >>> 8) & 0x3f];
}

function vp8x(width: number, height: number, flags = 0): number[] {
  const w = width - 1;
  const h = height - 1;
  return [flags, 0, 0, 0, w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, h & 0xff, (h >>> 8) & 0xff, (h >>> 16) & 0xff];
}

function testEnv(overrides: Partial<Env> = {}): Env {
  return {
    CMS_DB: env.CMS_DB,
    CMS_PASSWORD_PEPPER: "current-pepper-value-with-at-least-32-characters",
    CMS_AUTH_CHALLENGE_KEY: "challenge-key-value-with-at-least-32-characters",
    ...overrides,
  };
}

describe("CMS security helpers", () => {
  it("stores only a pepper-protected browser verifier and supports rotation", async () => {
    const verifier = "A".repeat(43);
    const current = testEnv();
    const protectedValue = await protectVerifier(current, verifier);

    expect(protectedValue).toHaveLength(43);
    expect(protectedValue).not.toBe(verifier);
    await expect(verifyProtectedVerifier(current, verifier, protectedValue)).resolves.toEqual({
      ok: true,
      usedPrevious: false,
    });

    const rotating = testEnv({
      CMS_PASSWORD_PEPPER: "new-pepper-value-with-at-least-32-characters",
      CMS_PASSWORD_PEPPER_PREVIOUS: "old-pepper-value-with-at-least-32-characters",
    });
    const oldValue = await protectVerifier(rotating, verifier, true);
    await expect(verifyProtectedVerifier(rotating, verifier, oldValue)).resolves.toEqual({
      ok: true,
      usedPrevious: true,
    });
  });

  it("uses deterministic, account-specific fake salts", async () => {
    const binding = testEnv();
    const first = await fakePasswordSalt(binding, "unknown-a");
    const repeat = await fakePasswordSalt(binding, "unknown-a");
    const other = await fakePasswordSalt(binding, "unknown-b");

    expect(first).toHaveLength(43);
    expect(first).toBe(repeat);
    expect(first).not.toBe(other);
  });

  it("accepts only the fixed browser credential parameters", () => {
    expect(validateClientCredential("A".repeat(43), "B".repeat(43), PASSWORD_ITERATIONS)).toEqual({
      verifier: "A".repeat(43),
      salt: "B".repeat(43),
      iterations: PASSWORD_ITERATIONS,
    });
    expect(() => validateClientCredential("A".repeat(43), "B".repeat(43), 10_000)).toThrow();
    expect(() => validateClientCredential("short", "B".repeat(43), PASSWORD_ITERATIONS)).toThrow();
  });

  it("sanitizes HTML, removes external images, and maps approved brand colours", () => {
    const output = renderBody(
      `<script>alert(1)</script>
       <span data-brand-color="orange" onclick="alert(2)">安全な色</span>
       <img src="https://attacker.example/a.webp" alt="外部画像">
       <a href="javascript:alert(3)">危険なリンク</a>`,
      "html",
    );

    expect(output).not.toContain("<script");
    expect(output).not.toContain("onclick");
    expect(output).not.toContain("attacker.example");
    expect(output).not.toContain("javascript:");
    expect(output).toContain('class="text-color-orange"');
  });

  it("rejects unsafe action destinations", () => {
    expect(safeActionUrl("https://example.com/form")).toBe("https://example.com/form");
    expect(safeActionUrl("/assets/document.pdf")).toBe("/assets/document.pdf");
    for (const unsafe of [
      "javascript:alert(1)",
      "data:text/html,test",
      "//attacker.example/path",
      "https://user:password@example.com/",
      "/assets/../admin/index.html",
      "/assets/%2e%2e/admin/index.html",
      "/assets/%2E./admin/index.html",
      "/assets/%5c..%5cadmin/index.html",
      "/assets/%00document.pdf",
      "https://example.com\\@attacker.example/",
    ]) {
      expect(() => safeActionUrl(unsafe)).toThrow();
    }
  });

  it("accepts coherent still WebP containers", () => {
    expect(webpDimensions(riff([{ type: "VP8 ", data: vp8(320, 180) }]))).toEqual({ width: 320, height: 180 });
    expect(webpDimensions(riff([
      { type: "VP8X", data: vp8x(640, 360) },
      { type: "JUNK", data: [1] },
      { type: "VP8 ", data: vp8(640, 360) },
    ]))).toEqual({ width: 640, height: 360 });
  });

  it("rejects malformed, metadata-bearing, duplicated, or dimension-conflicting WebP containers", () => {
    const malformed = new Uint8Array([
      0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50,
    ]);
    expect(webpDimensions(malformed)).toBeNull();

    expect(webpDimensions(riff([{ type: "EXIF", data: [] }, { type: "VP8 ", data: vp8(10, 10) }]))).toBeNull();
    expect(webpDimensions(riff([{ type: "VP8X", data: vp8x(10, 10, 1) }, { type: "VP8 ", data: vp8(10, 10) }]))).toBeNull();
    expect(webpDimensions(riff([
      { type: "VP8X", data: vp8x(10, 10) },
      { type: "VP8X", data: vp8x(10, 10) },
      { type: "VP8 ", data: vp8(10, 10) },
    ]))).toBeNull();
    expect(webpDimensions(riff([{ type: "VP8X", data: vp8x(10, 10) }, { type: "VP8 ", data: vp8(11, 10) }]))).toBeNull();
    expect(webpDimensions(riff([{ type: "VP8 ", data: vp8(1921, 10) }]))).toBeNull();
  });

  it("enforces the request body cap even without a Content-Length header", async () => {
    const oversized = new Request("https://example.test/api", {
      method: "POST",
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(7));
          controller.enqueue(new Uint8Array(7));
          controller.close();
        },
      }),
    });
    await expect(limitedRequestBytes(oversized, 10)).rejects.toMatchObject({ status: 413 });

    const exact = new Request("https://example.test/api", { method: "POST", body: new Uint8Array(10) });
    await expect(limitedRequestBytes(exact, 10)).resolves.toHaveLength(10);
  });
});
