package space.qu4nt.entanglementlib.security.crypto;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.crypto.encode.Base64;
import space.qu4nt.entanglementlib.security.crypto.encode.Hex;
import space.qu4nt.entanglementlib.security.crypto.hash.Hash;
import space.qu4nt.entanglementlib.security.crypto.rng.RNG;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.CryptoBackend;
import space.qu4nt.entanglementlib.security.provider.CryptoProviderConfig;
import space.qu4nt.entanglementlib.security.provider.CryptoProviders;
import space.qu4nt.entanglementlib.security.provider.DigestProvider;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

// 검증된 JDK 백엔드는 네이티브 바이너리 없이 항상 동작해야 한다 (환경 변수 게이트 없음)
@DisplayName("검증된 JDK 공급자 전환 검증 (네이티브 미사용)")
class VerifiedProviderTest {

    @BeforeEach
    void installVerified() {
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        null,
                        HeuristicArenaFactory.ArenaMode.CONFINED,
                        CryptoProviderConfig.verifiedDefaults()));
    }

    @Test
    @DisplayName("SHA-256 KAT - 검증된 JDK 백엔드")
    void sha256KnownAnswer() throws ELIBSecurityProcessException {
        final String expectedHex = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate("Hello, World!".getBytes(StandardCharsets.UTF_8), true);
            SensitiveDataContainer result = Hash.sha2(256, scope, input);
            assertEquals(expectedHex, toHex(result));
        }
    }

    @Test
    @DisplayName("SHA3-256 KAT - 검증된 JDK 백엔드")
    void sha3_256KnownAnswer() throws ELIBSecurityProcessException {
        // NIST 예시: SHA3-256("abc")
        final String expectedHex = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate("abc".getBytes(StandardCharsets.UTF_8), true);
            SensitiveDataContainer result = Hash.sha3(256, scope, input);
            assertEquals(expectedHex, toHex(result));
        }
    }

    @Test
    @DisplayName("Base64 인코딩 KAT 및 라운드트립 - 검증된 JDK 백엔드")
    void base64KnownAnswerAndRoundTrip() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate("Hello, World!".getBytes(StandardCharsets.UTF_8), true);
            SensitiveDataContainer encoded = Base64.encode(scope, input);
            assertEquals("SGVsbG8sIFdvcmxkIQ==", new String(bytes(encoded), StandardCharsets.US_ASCII));

            SensitiveDataContainer decoded = Base64.decode(scope, encoded);
            assertEquals("Hello, World!", new String(bytes(decoded), StandardCharsets.UTF_8));
        }
    }

    @Test
    @DisplayName("Hex 인코딩 KAT 및 라운드트립 - 검증된 JDK 백엔드")
    void hexKnownAnswerAndRoundTrip() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate(new byte[]{0x48, 0x69}, true); // "Hi"
            SensitiveDataContainer encoded = Hex.encode(scope, input);
            assertEquals("4869", new String(bytes(encoded), StandardCharsets.US_ASCII));

            SensitiveDataContainer decoded = Hex.decode(scope, encoded);
            assertArrayEquals(new byte[]{0x48, 0x69}, bytes(decoded));
        }
    }

    @Test
    @DisplayName("ChaCha20-Poly1305 RFC 8439 KAT 및 복호화 - 검증된 JDK 백엔드")
    void chacha20RfcVector() throws ELIBSecurityProcessException {
        final byte[] keyBytes = new byte[]{
                (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
                (byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b, (byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f,
                (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
                (byte) 0x98, (byte) 0x99, (byte) 0x9a, (byte) 0x9b, (byte) 0x9c, (byte) 0x9d, (byte) 0x9e, (byte) 0x9f
        };
        final byte[] nonceBytes = new byte[]{0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
        final byte[] aadBytes = new byte[]{0x50, 0x51, 0x52, 0x53, (byte) 0xc0, (byte) 0xc1, (byte) 0xc2, (byte) 0xc3, (byte) 0xc4, (byte) 0xc5, (byte) 0xc6, (byte) 0xc7};
        final String plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        final byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.US_ASCII);
        final String expectedCipherHex =
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
        final String expectedTagHex = "1ae10b594f09e26a7e902ecbd0600691";

        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer key = scope.allocate(keyBytes.clone(), true);
            SensitiveDataContainer nonce = scope.allocate(nonceBytes.clone(), true);
            SensitiveDataContainer aad = scope.allocate(aadBytes.clone(), true);
            SensitiveDataContainer pt = scope.allocate(plaintextBytes.clone(), true);

            SensitiveDataContainer ct = ChaCha20.encrypt(scope, key, nonce, aad, pt);
            byte[] ctBytes = bytes(ct);
            assertEquals(plaintextBytes.length + 16, ctBytes.length, "암호문 길이는 평문 + 16바이트 태그여야 합니다.");

            byte[] cipherOnly = new byte[ctBytes.length - 16];
            byte[] tagOnly = new byte[16];
            System.arraycopy(ctBytes, 0, cipherOnly, 0, cipherOnly.length);
            System.arraycopy(ctBytes, ctBytes.length - 16, tagOnly, 0, 16);
            assertEquals(expectedCipherHex, HexFormat.of().formatHex(cipherOnly), "RFC 8439 암호문이 일치해야 합니다.");
            assertEquals(expectedTagHex, HexFormat.of().formatHex(tagOnly), "RFC 8439 인증 태그가 일치해야 합니다.");

            SensitiveDataContainer back = ChaCha20.decrypt(scope, key, nonce, aad, ct);
            assertEquals(plaintext, new String(bytes(back), StandardCharsets.US_ASCII), "복호화 결과가 원문과 일치해야 합니다.");
        }
    }

    @Test
    @DisplayName("SecureRandom 기반 RNG - 검증된 JDK 백엔드")
    void rngLocalHardware() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer sdc = RNG.generateRNG(RNG.LOCAL_HARDWARE, scope, 32);
            MemorySegment seg = InternalNativeBridge.unwrapMemorySegment(sdc);
            assertEquals(32, seg.byteSize());
            boolean hasNonZero = false;
            for (long i = 0; i < 32; i++) {
                if (seg.get(ValueLayout.JAVA_BYTE, i) != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "난수 버퍼가 모두 0일 수는 없습니다.");
        }
    }

    @Test
    @DisplayName("검증 백엔드 미지원 연산은 명확히 예외를 던진다")
    void unsupportedOperationsThrow() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate("data".getBytes(StandardCharsets.UTF_8), true);
            // SHAKE(XOF)는 검증된 JDK 백엔드 미지원
            assertThrows(ELIBSecurityProcessException.class, () -> Hash.sha3Shake(256, 32, scope, input));
            // 양자 네트워크 엔트로피 전략 미지원
            assertThrows(ELIBSecurityProcessException.class, () -> RNG.generateRNG(RNG.QUANTUM_NETWORK, scope, 32));
        }
    }

    @Test
    @DisplayName("requiresNative 판정 - 검증 전용은 네이티브 불필요")
    void requiresNativeDecision() {
        assertFalse(CryptoProviderConfig.verifiedDefaults().requiresNative());
        assertTrue(CryptoProviderConfig.nativeDefaults().requiresNative());
        // 혼합: 기본은 검증, AEAD만 네이티브 -> 네이티브 필요
        assertTrue(CryptoProviderConfig.builder()
                .useVerifiedProviders()
                .aead(CryptoBackend.ENTLIB_NATIVE)
                .build()
                .requiresNative());
        // 네이티브 기본이지만 모든 기능에 커스텀/검증 주입 -> 네이티브 불필요
        assertFalse(CryptoProviderConfig.builder()
                .useNativeProviders()
                .digest(CryptoBackend.JDK_VERIFIED)
                .encoding(CryptoBackend.JDK_VERIFIED)
                .aead(CryptoBackend.JDK_VERIFIED)
                .random(CryptoBackend.JDK_VERIFIED)
                .build()
                .requiresNative());
    }

    @Test
    @DisplayName("사용자 정의 검증 공급자 주입이 레지스트리에 반영된다")
    void customProviderInjection() {
        final DigestProvider custom = new MarkerDigestProvider();
        CryptoProviders.install(CryptoProviderConfig.builder()
                .useVerifiedProviders()
                .digest(custom)
                .build());
        assertSame(custom, CryptoProviders.digest(), "주입한 커스텀 다이제스트 공급자가 그대로 설치되어야 합니다.");
        assertEquals("JDK 표준 (검증)", CryptoProviders.encoding().backendName(), "주입하지 않은 기능은 검증된 기본을 따라야 합니다.");
    }

    private static @NotNull String toHex(final SensitiveDataContainer sdc) {
        return HexFormat.of().formatHex(bytes(sdc));
    }

    private static byte @NotNull [] bytes(final SensitiveDataContainer sdc) {
        return InternalNativeBridge.unwrapMemorySegment(sdc).toArray(ValueLayout.JAVA_BYTE);
    }

    /// 주입 검증용 표식 공급자
    private static final class MarkerDigestProvider implements DigestProvider {
        @Override
        public SensitiveDataContainer sha2(@NotNull SDCScopeContext scope, int length, @NotNull SensitiveDataContainer input) {
            throw new UnsupportedOperationException("marker");
        }

        @Override
        public SensitiveDataContainer sha3(@NotNull SDCScopeContext scope, int length, @NotNull SensitiveDataContainer input) {
            throw new UnsupportedOperationException("marker");
        }

        @Override
        public SensitiveDataContainer shake(@NotNull SDCScopeContext scope, int variant, long outputBytes, @NotNull SensitiveDataContainer input) {
            throw new UnsupportedOperationException("marker");
        }

        @Override
        public @NotNull String backendName() {
            return "marker-custom";
        }
    }
}
