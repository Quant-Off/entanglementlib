package space.qu4nt.entanglementlib.security.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.crypto.hash.Hash;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.Function;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class SHA3HashTest {

    @BeforeAll
    static void setUp() {
        // 테스트 클래스 로드 시 1회만 네이티브 라이브러리를 초기화하여 성능 최적화
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        new NativeSpecContext(System.getenv("ENTLIB_NATIVE_BIN"), "entlib_native_ffi",
                                Function.chain(
                                        Function.withCalleeSecureBuffer(),
                                        Function.withCallerSecureBuffer(),
                                        Function.withHash(false))
                        ),
                        HeuristicArenaFactory.ArenaMode.CONFINED)
        );
    }

    @Test
    @DisplayName("SHA3-224 known answer test & 메모리 안전성 검증")
    void sha3_224StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA3-224 기댓값
        final String expectedHex = "853048fb8b11462b6100385633c0cc8dcdc6e2b8e376c28102bc84f2";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha3(224, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = InternalNativeBridge.unwrapMemorySegment(result);

            // [검증 A] 길이 검증
            assertEquals(28, resultSegmentAlias.byteSize(),
                    "SHA3-224 해시 결과는 정확히 28바이트(224비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SH3A-224 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA3-256 known answer test & 메모리 안전성 검증")
    void sha3_256StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA3-256 기댓값
        final String expectedHex = "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha3(256, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = InternalNativeBridge.unwrapMemorySegment(result);

            // [검증 A] 길이 검증
            assertEquals(32, resultSegmentAlias.byteSize(),
                    "SHA3-256 해시 결과는 정확히 32바이트(256비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA3-256 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA3-384 known answer test & 메모리 안전성 검증")
    void sha3_384StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA3-384 기댓값
        final String expectedHex = "aa9ad8a49f31d2ddcabbb7010a1566417cff803fef50eba239558826f872e468c5743e7f026b0a8e5b2d7a1cc465cdbe";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha3(384, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = InternalNativeBridge.unwrapMemorySegment(result);

            // [검증 A] 길이 검증
            assertEquals(48, resultSegmentAlias.byteSize(),
                    "SHA3-384 해시 결과는 정확히 32바이트(384비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA3-384 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA3-512 known answer test & 메모리 안전성 검증")
    void sha3_512StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA3-512 기댓값
        final String expectedHex = "38e05c33d7b067127f217d8c856e554fcff09c9320b8a5979ce2ff5d95dd27ba35d1fba50c562dfd1d6cc48bc9c5baa4390894418cc942d968f97bcb659419ed";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha3(512, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = InternalNativeBridge.unwrapMemorySegment(result);

            // [검증 A] 길이 검증
            assertEquals(64, resultSegmentAlias.byteSize(),
                    "SHA3-512 해시 결과는 정확히 32바이트(512비트)여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA3-512 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA3-SHAKE128 known answer test & 메모리 안전성 검증")
    void sha3_shake128StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA3-SHAKE128 (256비트) 기댓값
        final String expectedHex = "2bf5e6dee6079fad604f573194ba8426bd4d30eb13e8ba2edae70e529b570cbd";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha3Shake(128, 32, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = InternalNativeBridge.unwrapMemorySegment(result);

            // [검증 A] 길이 검증
            assertEquals(32, resultSegmentAlias.byteSize(),
                    "이 테스트에서 SHA3-SHAKE128 해시 결과는 정확히 256비트여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA3-SHAKE128 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }

    @Test
    @DisplayName("SHA3-SHAKE256 known answer test & 메모리 안전성 검증")
    void sha3_shake256StrictTest() throws Throwable {
        // 테스트 벡터
        final String inputText = "Hello, World!";
        // SHA3-SHAKE256 (512비트) 기댓값
        final String expectedHex = "b3be97bfd978833a65588ceae8a34cf59e95585af62063e6b89d0789f372424e8b0d1be4f21b40ce5a83a438473271e0661854f02d431db74e6904d6c347d757";
        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer result = Hash.sha3Shake(256, 64, context, inputData);

            assertNotNull(result, "해시 연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = InternalNativeBridge.unwrapMemorySegment(result);

            // [검증 A] 길이 검증
            assertEquals(64, resultSegmentAlias.byteSize(),
                    "이 테스트에서 SHA3-SHAKE256 해시 결과는 정확히 128자리여야 합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualHashBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE);
            String actualHex = HexFormat.of().formatHex(actualHashBytes);
            assertEquals(expectedHex, actualHex,
                    "계산된 해시값이 예상된 SHA3-SHAKE256 KAT(known answer test) 값과 정확히 일치해야 합니다.");
        }

        // 스코프 종료 후 메모리 보호 메커니즘 검증
        // 컨텍스트(context)가 close()된 이후, 해당 arena에 종속된 세그먼트에 접근을 시도하면
        // 자바 런타임이 IllegalStateException을 발생시켜야 안전한 소거 및 접근 차단이 입증됨
        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }
}