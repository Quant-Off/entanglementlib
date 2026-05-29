/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.protocol;

/// 폐쇄망 보안 채널의 와이어 포맷 상수입니다. 모든 정수 필드는 빅엔디언으로 직렬화됩니다.
///
/// # Wire Layout
/// 레코드 헤더(평문, 19바이트)
/// ```text
/// MAGIC(4) | VERSION(1) | opcode(1) | flags(1) | seq(8) | cipher_len(4)
/// ```
/// 본문은 ChaCha20-Poly1305 암호문이며 마지막 16바이트가 인증 태그입니다.
///
/// @author Q. T. Felix
public final class WireConstants {

    private WireConstants() {
        throw new AssertionError("cannot access");
    }

    /// 프로토콜 식별자 "ELI1"
    public static final int MAGIC = 0x45_4C_49_31;

    /// 프로토콜 버전
    public static final byte VERSION = 0x01;

    /// 암호 스위트 식별자 ChaCha20-Poly1305 + SHA3-256
    public static final byte SUITE_CHACHA20POLY1305_SHA3_256 = 0x01;

    /// 핸드셰이크 난수 길이
    public static final int RANDOM_LEN = 32;

    /// ChaCha20 대칭키 길이
    public static final int KEY_LEN = 32;

    /// ChaCha20 Nonce(IV) 길이
    public static final int IV_LEN = 12;

    /// Poly1305 인증 태그 길이
    public static final int TAG_LEN = 16;

    /// 레코드 헤더 길이
    public static final int HEADER_LEN = 19;

    /// 단일 레코드 본문 최대 크기 (1 MiB)
    public static final int MAX_FRAME = 1_048_576;

    /// 사전 공유 키 최소 길이
    public static final int MIN_PSK_LEN = 32;

    /// 핸드셰이크 전체 제한 시간 (밀리초)
    public static final int HANDSHAKE_TIMEOUT_MILLIS = 5_000;

    /// 유휴 읽기 제한 시간 (밀리초)
    public static final int IDLE_READ_TIMEOUT_MILLIS = 30_000;

    /// 기본 최대 동시 연결 수
    public static final int DEFAULT_MAX_CONNECTIONS = 64;

    /// 키 유도 도메인 분리 라벨
    public static final String LABEL_K_C2S = "iss1:k_c2s";
    public static final String LABEL_K_S2C = "iss1:k_s2c";
    public static final String LABEL_IV_C2S = "iss1:iv_c2s";
    public static final String LABEL_IV_S2C = "iss1:iv_s2c";
    public static final String LABEL_FINISHED = "iss1:fin";

    /// PSK 정규화 도메인 분리 접두 바이트
    public static final byte PSK_CANON_DOMAIN = 0x00;

    /// Finished 트랜스크립트 도메인 분리 바이트
    public static final byte FINISHED_CLIENT = 0x10;
    public static final byte FINISHED_SERVER = 0x11;
}
