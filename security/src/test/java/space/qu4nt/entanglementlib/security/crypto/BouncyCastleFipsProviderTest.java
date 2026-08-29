package space.qu4nt.entanglementlib.security.crypto;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterAll;
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

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// BouncyCastle FIPS 백엔드는 네이티브 바이너리 없이 항상 동작해야 한다 (bc-fips는 testImplementation)
@DisplayName("BouncyCastle FIPS 공급자 전환 검증(네이티브 미사용)")
class BouncyCastleFipsProviderTest {

    private static final byte[] RFC8439_KEY = HexFormat.of().parseHex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static final byte[] RFC8439_NONCE = HexFormat.of().parseHex("070000004041424344454647");
    private static final byte[] RFC8439_AAD = HexFormat.of().parseHex("50515253c0c1c2c3c4c5c6c7");
    private static final String RFC8439_PLAINTEXT =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    private static final String RFC8439_CIPHER_HEX =
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    private static final String RFC8439_TAG_HEX = "1ae10b594f09e26a7e902ecbd0600691";

    @BeforeEach
    void installBouncyCastleFips() {
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        null,
                        HeuristicArenaFactory.ArenaMode.CONFINED,
                        CryptoProviderConfig.bouncyCastleFipsDefaults()));
    }

    @AfterAll
    static void restoreVerifiedDefaults() {
        CryptoProviders.install(CryptoProviderConfig.verifiedDefaults());
    }

    @Test
    @DisplayName("모듈 자체 시험 통과 및 공급자 설치 확인")
    void moduleReadyAndInstalled() {
        assertTrue(FipsStatus.isReady(), "bc-fips 모듈이 기동 자체 시험을 통과해야 합니다.");
        assertFalse(FipsStatus.isErrorStatus());
        assertTrue(CryptoProviders.digest().backendName().startsWith("BouncyCastle FIPS"));
        assertTrue(CryptoProviders.encoding().backendName().startsWith("BouncyCastle FIPS"));
        assertTrue(CryptoProviders.aead().backendName().startsWith("BouncyCastle FIPS"));
        assertTrue(CryptoProviders.random().backendName().contains("HMAC-DRBG-SHA512"));
    }

    @Test
    @DisplayName("SHA-2 KAT - BouncyCastle FIPS 백엔드")
    void sha2KnownAnswer() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate("Hello, World!".getBytes(StandardCharsets.UTF_8), true);
            assertEquals("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
                    toHex(Hash.sha2(256, scope, input)));

            SensitiveDataContainer abc = scope.allocate("abc".getBytes(StandardCharsets.UTF_8), true);
            assertEquals("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                            + "8086072ba1e7cc2358baeca134c825a7",
                    toHex(Hash.sha2(384, scope, abc)));
        }
    }

    @Test
    @DisplayName("SHA-3 KAT - BouncyCastle FIPS 백엔드")
    void sha3KnownAnswer() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer abc = scope.allocate("abc".getBytes(StandardCharsets.UTF_8), true);
            assertEquals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                    toHex(Hash.sha3(256, scope, abc)));
        }
    }

    @Test
    @DisplayName("SHAKE(XOF) KAT - JDK 백엔드가 지원하지 않는 연산")
    void shakeKnownAnswer() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer empty = scope.allocate(new byte[0], true);
            assertEquals("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
                    toHex(Hash.sha3Shake(128, 32, scope, empty)));
            assertEquals("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                    toHex(Hash.sha3Shake(256, 32, scope, empty)));

            // XOF 접두 성질 - 짧은 출력은 긴 출력의 접두사여야 한다
            String shortOut = toHex(Hash.sha3Shake(256, 16, scope, empty));
            String longOut = toHex(Hash.sha3Shake(256, 64, scope, empty));
            assertTrue(longOut.startsWith(shortOut), "XOF 출력은 길이를 늘려도 접두사가 유지되어야 합니다.");
        }
    }

    @Test
    @DisplayName("Base64 및 Hex 인코딩 KAT - BouncyCastle FIPS 백엔드")
    void encodingKnownAnswerAndRoundTrip() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate("Hello, World!".getBytes(StandardCharsets.UTF_8), true);
            SensitiveDataContainer encoded = Base64.encode(scope, input);
            assertEquals("SGVsbG8sIFdvcmxkIQ==", new String(bytes(encoded), StandardCharsets.US_ASCII));
            assertEquals("Hello, World!", new String(bytes(Base64.decode(scope, encoded)), StandardCharsets.UTF_8));

            SensitiveDataContainer hi = scope.allocate(new byte[]{0x48, 0x69}, true);
            SensitiveDataContainer hex = Hex.encode(scope, hi);
            assertEquals("4869", new String(bytes(hex), StandardCharsets.US_ASCII));
            assertArrayEquals(new byte[]{0x48, 0x69}, bytes(Hex.decode(scope, hex)));
        }
    }

    @Test
    @DisplayName("ChaCha20-Poly1305 RFC 8439 KAT 및 복호화 - BouncyCastle FIPS 백엔드")
    void chacha20RfcVector() throws ELIBSecurityProcessException {
        final byte[] plaintextBytes = RFC8439_PLAINTEXT.getBytes(StandardCharsets.US_ASCII);
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer key = scope.allocate(RFC8439_KEY.clone(), true);
            SensitiveDataContainer nonce = scope.allocate(RFC8439_NONCE.clone(), true);
            SensitiveDataContainer aad = scope.allocate(RFC8439_AAD.clone(), true);
            SensitiveDataContainer pt = scope.allocate(plaintextBytes.clone(), true);

            SensitiveDataContainer ct = ChaCha20.encrypt(scope, key, nonce, aad, pt);
            byte[] ctBytes = bytes(ct);
            assertEquals(plaintextBytes.length + 16, ctBytes.length, "암호문 길이는 평문 + 16바이트 태그여야 합니다.");
            assertEquals(RFC8439_CIPHER_HEX + RFC8439_TAG_HEX, HexFormat.of().formatHex(ctBytes),
                    "RFC 8439 암호문과 인증 태그가 일치해야 합니다.");

            SensitiveDataContainer back = ChaCha20.decrypt(scope, key, nonce, aad, ct);
            assertEquals(RFC8439_PLAINTEXT, new String(bytes(back), StandardCharsets.US_ASCII));
        }
    }

    @Test
    @DisplayName("변조된 암호문은 인증 태그 검증에서 거부된다")
    void tamperedCiphertextRejected() throws ELIBSecurityProcessException {
        final byte[] plaintextBytes = RFC8439_PLAINTEXT.getBytes(StandardCharsets.US_ASCII);
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer key = scope.allocate(RFC8439_KEY.clone(), true);
            SensitiveDataContainer nonce = scope.allocate(RFC8439_NONCE.clone(), true);
            SensitiveDataContainer aad = scope.allocate(RFC8439_AAD.clone(), true);
            SensitiveDataContainer pt = scope.allocate(plaintextBytes.clone(), true);

            byte[] tampered = bytes(ChaCha20.encrypt(scope, key, nonce, aad, pt));
            tampered[tampered.length - 1] ^= 0x01;
            SensitiveDataContainer bad = scope.allocate(tampered, true);

            ELIBSecurityProcessException thrown = assertThrows(ELIBSecurityProcessException.class,
                    () -> ChaCha20.decrypt(scope, key, nonce, aad, bad),
                    "태그가 변조된 암호문은 복호화되면 안 됩니다.");
            assertTrue(thrown.getMessage().contains("인증 태그 검증에 실패"),
                    "무결성 위반은 일반 오류가 아니라 태그 검증 실패로 보고되어야 합니다 -> " + thrown.getMessage());
        }
    }

    @Test
    @DisplayName("JDK 백엔드로 암호화한 결과를 BouncyCastle FIPS 백엔드로 복호화한다")
    void crossBackendWireFormatCompatibility() throws ELIBSecurityProcessException {
        final byte[] plaintextBytes = RFC8439_PLAINTEXT.getBytes(StandardCharsets.US_ASCII);
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer key = scope.allocate(RFC8439_KEY.clone(), true);
            SensitiveDataContainer nonce = scope.allocate(RFC8439_NONCE.clone(), true);
            SensitiveDataContainer aad = scope.allocate(RFC8439_AAD.clone(), true);
            SensitiveDataContainer pt = scope.allocate(plaintextBytes.clone(), true);

            CryptoProviders.install(CryptoProviderConfig.verifiedDefaults());
            SensitiveDataContainer ct = ChaCha20.encrypt(scope, key, nonce, aad, pt);

            CryptoProviders.install(CryptoProviderConfig.bouncyCastleFipsDefaults());
            SensitiveDataContainer back = ChaCha20.decrypt(scope, key, nonce, aad, ct);
            assertEquals(RFC8439_PLAINTEXT, new String(bytes(back), StandardCharsets.US_ASCII),
                    "두 백엔드는 동일한 '암호문 || 태그' 형식을 사용해야 합니다.");
        }
    }

    @Test
    @DisplayName("SP 800-90A DRBG 기반 RNG - BouncyCastle FIPS 백엔드")
    void rngLocalHardware() throws ELIBSecurityProcessException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer first = RNG.generateRNG(RNG.LOCAL_HARDWARE, scope, 32);
            SensitiveDataContainer second = RNG.generateRNG(RNG.LOCAL_HARDWARE, scope, 32);

            MemorySegment segment = InternalNativeBridge.unwrapMemorySegment(first);
            assertEquals(32, segment.byteSize());
            boolean hasNonZero = false;
            for (long i = 0; i < 32; i++) {
                if (segment.get(ValueLayout.JAVA_BYTE, i) != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "난수 버퍼가 모두 0일 수는 없습니다.");
            assertFalse(java.util.Arrays.equals(bytes(first), bytes(second)), "연속 생성 결과가 같을 수 없습니다.");
        }
    }

    @Test
    @DisplayName("양자 네트워크 엔트로피 전략은 BouncyCastle FIPS 백엔드에서 거부된다")
    void quantumNetworkStrategyRejected() {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            assertThrows(ELIBSecurityProcessException.class, () -> RNG.generateRNG(RNG.QUANTUM_NETWORK, scope, 32));
        }
    }

    @Test
    @DisplayName("approved-only 모드에서 ChaCha20-Poly1305는 명확한 예외로 거부된다")
    void approvedOnlyModeRejectsChaCha20() throws InterruptedException {
        // approved-only 모드는 스레드 단위이며 되돌릴 수 없으므로 전용 스레드에서 검증한다
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final Thread worker = new Thread(() -> {
            CryptoServicesRegistrar.setApprovedOnlyMode(true);
            try (SDCScopeContext scope = new SDCScopeContext()) {
                SensitiveDataContainer key = scope.allocate(RFC8439_KEY.clone(), true);
                SensitiveDataContainer nonce = scope.allocate(RFC8439_NONCE.clone(), true);
                SensitiveDataContainer pt = scope.allocate("data".getBytes(StandardCharsets.UTF_8), true);
                ChaCha20.encrypt(scope, key, nonce, null, pt);
            } catch (Throwable t) {
                failure.set(t);
            }
        }, "bc-fips-approved-only");

        worker.start();
        worker.join();

        assertInstanceOf(ELIBSecurityProcessException.class, failure.get(),
                "approved-only 모드에서는 FIPS 미승인 AEAD가 명확한 예외로 거부되어야 합니다.");
        assertFalse(CryptoServicesRegistrar.isInApprovedOnlyMode(), "테스트 스레드의 모드는 오염되지 않아야 합니다.");
    }

    @Test
    @DisplayName("requiresNative 판정 - BouncyCastle FIPS 전용은 네이티브 불필요")
    void requiresNativeDecision() {
        assertFalse(CryptoProviderConfig.bouncyCastleFipsDefaults().requiresNative());
        // 네이티브 기본이지만 모든 기능을 BC FIPS로 덮으면 네이티브 불필요
        assertFalse(CryptoProviderConfig.builder()
                .useNativeProviders()
                .digest(CryptoBackend.BOUNCY_CASTLE_FIPS)
                .encoding(CryptoBackend.BOUNCY_CASTLE_FIPS)
                .aead(CryptoBackend.BOUNCY_CASTLE_FIPS)
                .random(CryptoBackend.BOUNCY_CASTLE_FIPS)
                .build()
                .requiresNative());
    }

    @Test
    @DisplayName("기능별 혼합 - 다이제스트만 BC FIPS, 나머지는 검증된 JDK")
    void mixedBackendResolution() throws ELIBSecurityProcessException {
        CryptoProviders.install(CryptoProviderConfig.builder()
                .useVerifiedProviders()
                .digest(CryptoBackend.BOUNCY_CASTLE_FIPS)
                .build());

        assertEquals("BouncyCastle FIPS SHS (검증)", CryptoProviders.digest().backendName());
        assertEquals("JDK 표준 (검증)", CryptoProviders.encoding().backendName());
        assertEquals("JDK SecureRandom (검증)", CryptoProviders.random().backendName());

        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer empty = scope.allocate(new byte[0], true);
            // JDK 백엔드가 지원하지 않는 SHAKE가 혼합 구성에서는 동작해야 한다
            assertEquals("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
                    toHex(Hash.sha3Shake(128, 32, scope, empty)));
        }
    }

    private static @NotNull String toHex(final SensitiveDataContainer sdc) {
        return HexFormat.of().formatHex(bytes(sdc));
    }

    private static byte @NotNull [] bytes(final SensitiveDataContainer sdc) {
        return InternalNativeBridge.unwrapMemorySegment(sdc).toArray(ValueLayout.JAVA_BYTE);
    }
}
