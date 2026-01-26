/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.tls;

/// TLS 핸드셰이크 메시지 타입을 정의하는 클래스입니다.
///
/// 포스트-퀀텀 TLS 핸드셰이크 프로토콜:
/// 1. ClientHello: 클라이언트가 공개키와 지원 알고리즘 목록 전송
/// 2. ServerHello: 서버가 자신의 공개키와 캡슐화된 공유 비밀 전송
/// 3. Finished: 양측이 핸드셰이크 완료 확인
///
/// @author Q. T. Felix
/// @see Server
/// @since 1.1.0
public final class HandshakeMessage {

    private HandshakeMessage() {
    }

    //
    // Message Types
    //

    /// 클라이언트 Hello 메시지
    /// 클라이언트가 연결 시작 시 전송하며, 공개키와 지원 알고리즘 포함
    public static final byte CLIENT_HELLO = 0x01;

    /// 서버 Hello 메시지
    /// 서버가 ClientHello에 응답하여 전송하며, 공개키와 캡슐화 결과 포함
    public static final byte SERVER_HELLO = 0x02;

    /// 인증서 메시지 (선택적)
    /// 서버 또는 클라이언트의 인증서 체인
    public static final byte CERTIFICATE = 0x03;

    /// 인증서 검증 메시지 (선택적)
    /// 인증서의 개인키 소유 증명
    public static final byte CERTIFICATE_VERIFY = 0x04;

    /// 핸드셰이크 완료 메시지
    /// 핸드셰이크 과정의 무결성 확인
    public static final byte FINISHED = 0x05;

    /// 키 업데이트 메시지
    /// 세션 중 키 갱신 요청
    public static final byte KEY_UPDATE = 0x06;

    /// 경고 메시지
    /// 오류 또는 경고 상황 알림
    public static final byte ALERT = 0x07;

    //
    // Alert Types
    //

    /// 경고 수준: 경고 (연결 유지)
    public static final byte ALERT_LEVEL_WARNING = 0x01;

    /// 경고 수준: 치명적 (연결 종료)
    public static final byte ALERT_LEVEL_FATAL = 0x02;

    //
    // Alert Descriptions
    //

    /// 정상 종료
    public static final byte ALERT_CLOSE_NOTIFY = 0x00;

    /// 예상치 못한 메시지
    public static final byte ALERT_UNEXPECTED_MESSAGE = 0x0A;

    /// 잘못된 MAC
    public static final byte ALERT_BAD_RECORD_MAC = 0x14;

    /// 핸드셰이크 실패
    public static final byte ALERT_HANDSHAKE_FAILURE = 0x28;

    /// 잘못된 인증서
    public static final byte ALERT_BAD_CERTIFICATE = 0x2A;

    /// 인증서 만료
    public static final byte ALERT_CERTIFICATE_EXPIRED = 0x2D;

    /// 알 수 없는 CA
    public static final byte ALERT_UNKNOWN_CA = 0x30;

    /// 프로토콜 버전 불일치
    public static final byte ALERT_PROTOCOL_VERSION = 0x46;

    /// 내부 오류
    public static final byte ALERT_INTERNAL_ERROR = 0x50;

    //
    // Protocol Version
    //

    /// 프로토콜 버전 1.0
    public static final byte VERSION_1_0 = 0x01;

    //
    // Key Exchange Algorithms
    //

    /// ML-KEM-512
    public static final byte KE_ML_KEM_512 = 0x01;

    /// ML-KEM-768
    public static final byte KE_ML_KEM_768 = 0x02;

    /// ML-KEM-1024
    public static final byte KE_ML_KEM_1024 = 0x03;

    /// X25519
    public static final byte KE_X25519 = 0x10;

    /// X25519 + ML-KEM-768 (하이브리드)
    public static final byte KE_X25519_ML_KEM_768 = 0x20;

    //
    // Utility Methods
    //

    /// 메시지 타입의 이름을 반환합니다.
    ///
    /// @param type 메시지 타입
    /// @return 메시지 타입 이름
    public static String getTypeName(byte type) {
        return switch (type) {
            case CLIENT_HELLO -> "ClientHello";
            case SERVER_HELLO -> "ServerHello";
            case CERTIFICATE -> "Certificate";
            case CERTIFICATE_VERIFY -> "CertificateVerify";
            case FINISHED -> "Finished";
            case KEY_UPDATE -> "KeyUpdate";
            case ALERT -> "Alert";
            default -> "Unknown(" + type + ")";
        };
    }

    /// 키 교환 알고리즘의 이름을 반환합니다.
    ///
    /// @param algorithm 알고리즘 식별자
    /// @return 알고리즘 이름
    public static String getKeyExchangeName(byte algorithm) {
        return switch (algorithm) {
            case KE_ML_KEM_512 -> "ML-KEM-512";
            case KE_ML_KEM_768 -> "ML-KEM-768";
            case KE_ML_KEM_1024 -> "ML-KEM-1024";
            case KE_X25519 -> "X25519";
            case KE_X25519_ML_KEM_768 -> "X25519+ML-KEM-768";
            default -> "Unknown(" + algorithm + ")";
        };
    }
}
