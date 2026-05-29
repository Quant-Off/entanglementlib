package space.qu4nt.entanglementlib.security.communication;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.nio.channels.ByteChannel;
import java.util.Objects;

/// 폐쇄망(air-gapped / closed network) 환경을 위한 TLS 파사드입니다.
///
/// 공개 인터넷의 인증 기관(CA) 신뢰 체인을 전적으로 배제하고, 사전 공유 신뢰
/// (PSK 또는 핀고정 키)에 기반하여 `entlib-native` 보안 원시연산만으로 보안 세션을 수립합니다.
/// 모든 민감 데이터는 [SensitiveDataContainer]로 소유권이 통제되며, JVM `heap`에 노출되지 않습니다.
///
/// # 핸드셰이크 파이프라인 (설계)
/// 폐쇄망 세션은 다음 단계로 수립됩니다.
/// 1. 트랜스크립트 해싱 -> SHA-3-256 ([space.qu4nt.entanglementlib.security.crypto.hash.Hash])
///    (`entlib-native` 원샷 FFI 노출 완료)
/// 2. 키 확립 -> ML-KEM(양자 내성) 캡슐화/역캡슐화 (네이티브 FFI 미노출)
/// 3. 키 유도 -> HKDF(SHA-3 기반) (네이티브 FFI 미노출)
/// 4. 레코드 보호 -> ChaCha20-Poly1305 AEAD
///    ([space.qu4nt.entanglementlib.security.crypto.ChaCha20]) (네이티브 FFI 미노출)
/// 5. Nonce 생성 -> RNG ([space.qu4nt.entanglementlib.security.crypto.rng.RNG]) (네이티브 FFI 미노출)
///
/// # Status
/// 현재 노출된 원샷 FFI 함수는 base64 / hex / SHA-2 / SHA-3(SHAKE)뿐입니다. 키 확립(KEM),
/// 레코드 AEAD, RNG가 네이티브 경계에 노출되기 전까지 핸드셰이크 및 레코드 입출력은
/// [ELIBSecurityProcessException]을 던집니다. 이 클래스는 세션 생명주기 및 자원 소거 구조를
/// 갖춘 설계 골격입니다.
///
/// @author Q. T. Felix
public final class ExternalTLS {

    private ExternalTLS() {
        throw new UnsupportedOperationException("cannot access");
    }

    /// 세션 참가자 역할입니다.
    public enum Role {
        CLIENT,
        SERVER
    }

    /// 핸드셰이크 진행 상태입니다.
    public enum HandshakeState {
        NEW,
        IN_PROGRESS,
        ESTABLISHED,
        FAILED,
        CLOSED
    }

    /// 폐쇄망에서 사용할 암호 스위트 식별자입니다.
    public enum CipherSuite {
        /// PQC 하이브리드 권장 스위트 (식별자 정의)
        ECLOSED_MLKEM768_CHACHA20POLY1305_SHA3_256
    }

    /// 폐쇄망 TLS 세션 구성입니다.
    public static final class Config {
        private final Role role;
        private final CipherSuite cipherSuite;
        private final @Nullable SensitiveDataContainer presharedKey;

        private Config(final Role role, final CipherSuite cipherSuite, final @Nullable SensitiveDataContainer presharedKey) {
            this.role = Objects.requireNonNull(role, "role");
            this.cipherSuite = Objects.requireNonNull(cipherSuite, "cipherSuite");
            this.presharedKey = presharedKey;
        }

        public static Builder builder(final @NotNull Role role) {
            return new Builder(role);
        }

        public Role getRole() {
            return role;
        }

        public CipherSuite getCipherSuite() {
            return cipherSuite;
        }

        public @Nullable SensitiveDataContainer getPresharedKey() {
            return presharedKey;
        }

        public static final class Builder {
            private final Role role;
            private CipherSuite cipherSuite = CipherSuite.ECLOSED_MLKEM768_CHACHA20POLY1305_SHA3_256;
            private @Nullable SensitiveDataContainer presharedKey;

            private Builder(final @NotNull Role role) {
                this.role = Objects.requireNonNull(role, "role");
            }

            public Builder cipherSuite(final @NotNull CipherSuite cipherSuite) {
                this.cipherSuite = Objects.requireNonNull(cipherSuite, "cipherSuite");
                return this;
            }

            public Builder presharedKey(final @Nullable SensitiveDataContainer presharedKey) {
                this.presharedKey = presharedKey;
                return this;
            }

            public Config build() {
                return new Config(role, cipherSuite, presharedKey);
            }
        }
    }

    /// 전달된 채널 위에 폐쇄망 TLS 세션을 엽니다. 세션은 자체 [SDCScopeContext]를 소유하며
    /// [ClosedTlsSession#close()] 시 세션 내 모든 민감 데이터가 일괄 소거됩니다.
    ///
    /// @param channel 하부 양방향 바이트 채널 (예: SocketChannel)
    /// @param config  세션 구성
    /// @return 핸드셰이크 이전 상태([HandshakeState#NEW])의 세션
    public static @NotNull ClosedTlsSession open(final @NotNull ByteChannel channel, final @NotNull Config config) {
        if (channel == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 채널입니다!");
        if (config == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 세션 구성입니다!");
        return new ClosedTlsSession(channel, config);
    }

    /// 단일 폐쇄망 TLS 세션을 표현하는 객체입니다. 세션 생명주기 동안의 모든 민감 데이터를
    /// 추적하고 [#close()] 시 안전하게 소거합니다.
    public static final class ClosedTlsSession implements AutoCloseable {

        private final ByteChannel channel;
        private final Config config;
        private final SDCScopeContext scope;
        private volatile HandshakeState state;

        private ClosedTlsSession(final ByteChannel channel, final Config config) {
            this.channel = channel;
            this.config = config;
            this.scope = new SDCScopeContext();
            this.state = HandshakeState.NEW;
        }

        /// 폐쇄망 핸드셰이크를 수행합니다.
        ///
        /// @throws ELIBSecurityProcessException 키 확립(KEM)·레코드 AEAD·RNG가 네이티브 FFI에
        ///                                      노출되기 전까지 항상 발생
        public void handshake() throws ELIBSecurityProcessException {
            this.state = HandshakeState.IN_PROGRESS;
            try {
                throw new ELIBSecurityProcessException(
                        "폐쇄망 TLS 핸드셰이크는 ML-KEM 키 확립, ChaCha20-Poly1305 레코드 AEAD, " +
                        "RNG nonce 생성을 필요로 하지만 아직 entlib-native FFI에 노출되지 않았습니다 " +
                        "(현재 base64/hex/SHA-2/SHA-3만 노출됨)");
            } catch (ELIBSecurityProcessException e) {
                this.state = HandshakeState.FAILED;
                throw e;
            }
        }

        /// 수립된 세션 위로 평문 컨테이너를 AEAD 보호하여 전송합니다.
        ///
        /// @throws ELIBSecurityProcessException 레코드 AEAD가 네이티브 FFI에 노출되기 전까지 항상 발생
        public void writeSecure(final @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException {
            requireEstablished();
            throw new ELIBSecurityProcessException(
                    "레코드 보호(ChaCha20-Poly1305)는 아직 entlib-native FFI에 노출되지 않았습니다");
        }

        /// 수립된 세션에서 AEAD 보호된 레코드를 수신하여 복호화한 평문 컨테이너를 반환합니다.
        ///
        /// @throws ELIBSecurityProcessException 레코드 AEAD가 네이티브 FFI에 노출되기 전까지 항상 발생
        public @NotNull SensitiveDataContainer readSecure() throws ELIBSecurityProcessException {
            requireEstablished();
            throw new ELIBSecurityProcessException(
                    "레코드 복호화(ChaCha20-Poly1305)는 아직 entlib-native FFI에 노출되지 않았습니다");
        }

        public HandshakeState state() {
            return state;
        }

        public Config config() {
            return config;
        }

        private void requireEstablished() throws ELIBSecurityProcessException {
            if (state != HandshakeState.ESTABLISHED)
                throw new ELIBSecurityProcessException("세션이 수립되지 않았습니다 (현재 상태: " + state + ")");
        }

        /// 세션을 종료하고 세션 스코프 내 모든 민감 데이터를 소거한 뒤 하부 채널을 닫습니다.
        @Override
        public void close() {
            try {
                scope.close();
            } finally {
                this.state = HandshakeState.CLOSED;
                try {
                    if (channel.isOpen())
                        channel.close();
                } catch (Exception ignored) {
                    // 채널 종료 실패는 세션 소거 결과에 영향을 주지 않음
                }
            }
        }
    }
}
