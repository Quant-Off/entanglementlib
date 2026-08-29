import { describe, expect, it } from "vite-plus/test";
import {
  decodeBase64,
  decodeUtf8Strict,
  formatBytes,
  toHexDump,
} from "../src/app/core/value-format.ts";

describe("formatBytes", () => {
  it("단위를 올바르게 환산한다", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.0 KiB");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(1048576)).toBe("1.0 MiB");
  });

  it("비정상 입력은 0 B 로 처리한다", () => {
    expect(formatBytes(-1)).toBe("0 B");
    expect(formatBytes(Number.NaN)).toBe("0 B");
  });
});

describe("decodeBase64", () => {
  it("base64 를 바이트로 복원한다", () => {
    expect(Array.from(decodeBase64("aGVsbG8="))).toEqual([104, 101, 108, 108, 111]);
    expect(decodeBase64("").length).toBe(0);
  });
});

describe("decodeUtf8Strict", () => {
  it("유효한 UTF-8 텍스트를 복원한다", () => {
    const bytes = new TextEncoder().encode("한글 텍스트\n둘째 줄");
    expect(decodeUtf8Strict(bytes)).toBe("한글 텍스트\n둘째 줄");
  });

  it("잘못된 UTF-8 은 null 을 반환한다", () => {
    expect(decodeUtf8Strict(new Uint8Array([0xff, 0xfe, 0x00]))).toBeNull();
  });

  it("제어 문자가 섞이면 null 을 반환한다", () => {
    expect(decodeUtf8Strict(new Uint8Array([0x41, 0x01, 0x42]))).toBeNull();
  });
});

describe("toHexDump", () => {
  it("오프셋과 ASCII 컬럼을 포함한다", () => {
    const dump = toHexDump(new Uint8Array([0x48, 0x69, 0x00, 0xff]));
    expect(dump).toContain("00000000");
    expect(dump).toContain("48 69 00 ff");
    expect(dump).toContain("Hi..");
  });

  it("최대 바이트를 넘으면 생략 표시를 남긴다", () => {
    const dump = toHexDump(new Uint8Array(20).fill(0x41), 16);
    expect(dump).toContain("4 바이트 생략");
  });
});
