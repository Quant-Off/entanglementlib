package space.qu4nt.entanglementlib.security.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.crypto.hash.Hash;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.Function;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class SHA2HashTest {

    @BeforeAll
    static void setUp() {
        // 테스트 클래스 로드 시 1회만 네이티브 라이브러리를 초기화하여 성능 최적화
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        new NativeSpecContext("/Library/Quant/Repository/projects/entanglementlib/entlib-native/target/debug", "entlib_native_ffi",
                                Function.chain(
                                        Function.withCalleeSecureBuffer(),
                                        Function.withCallerSecureBuffer(),
                                        Function.withHash(true))),
                        HeuristicArenaFactory.ArenaMode.CONFINED)
        );
    }

    @Test
    @DisplayName("SHA-224 known answer test & 메모리 안전성 검증")
    void sha224StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA-224 기댓값
        final String expectedHex = "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha2(224, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = result.getMemorySegment();

            // [검증 A] 길이 검증
            assertEquals(28, resultSegmentAlias.byteSize(),
                    "SHA-224 해시 결과는 정확히 28바이트(224비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA-224 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA-256 known answer test & 메모리 안전성 검증")
    void sha256StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA-256 기댓값
        final String expectedHex = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha2(256, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = result.getMemorySegment();

            // [검증 A] 길이 검증
            assertEquals(32, resultSegmentAlias.byteSize(),
                    "SHA-256 해시 결과는 정확히 32바이트(256비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA-256 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA-384 known answer test & 메모리 안전성 검증")
    void sha384StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA-384 기댓값
        final String expectedHex = "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha2(384, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = result.getMemorySegment();

            // [검증 A] 길이 검증
            assertEquals(48, resultSegmentAlias.byteSize(),
                    "SHA-384 해시 결과는 정확히 48바이트(384비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA-384 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA-512 known answer test & 메모리 안전성 검증")
    void sha512StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA-512 기댓값
        final String expectedHex = "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha2(512, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = result.getMemorySegment();

            // [검증 A] 길이 검증
            assertEquals(64, resultSegmentAlias.byteSize(),
                    "SHA-512 해시 결과는 정확히 64바이트(512비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA-512 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () -> {
            resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0);
        }, "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }
}