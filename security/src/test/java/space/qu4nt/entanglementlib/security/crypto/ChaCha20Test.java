package space.qu4nt.entanglementlib.security.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.core.util.wrapper.Hex;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.Function;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class ChaCha20Test {

    @BeforeAll
    static void setUp() {
        // 테스트 클래스 로드 시 1회만 네이티브 라이브러리를 초기화하여 성능 최적화
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        new NativeSpecContext("/Library/Quant/Repository/projects/entanglementlib/entlib-native/target/debug", "entlib_native_ffi",
                                Function.Callee_Secure_Buffer_Data,
                                Function.Callee_Secure_Buffer_Len,
                                Function.Callee_Secure_Buffer_Free,
                                Function.Caller_Secure_Buffer_Wipe,
                                Function.ChaCha20_Poly1305_Encrypt,
                                Function.ChaCha20_Poly1305_Decrypt),
                        HeuristicArenaFactory.ArenaMode.CONFINED)
        );
    }

    @Test
    @DisplayName("ChaCha20 known answer test & 메모리 안전성 검증")
    void chacha20Test() throws Throwable {
        // 테스트 벡터
        final String inputText = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        // 기댓값
        final byte[] expected = new byte[]{
                (byte) 0xd3, 0x1a, (byte) 0x8d, 0x34, 0x64, (byte) 0x8e, 0x60, (byte) 0xdb, 0x7b, (byte) 0x86,
                (byte) 0xaf, (byte) 0xbc, 0x53, (byte) 0xef, 0x7e, (byte) 0xc2, (byte) 0xa4, (byte) 0xad,
                (byte) 0xed, 0x51, 0x29, 0x6e, 0x08, (byte) 0xfe, (byte) 0xa9, (byte) 0xe2, (byte) 0xb5,
                (byte) 0xa7, 0x36, (byte) 0xee, 0x62, (byte) 0xd6, 0x3d, (byte) 0xbe, (byte) 0xa4, 0x5e,
                (byte) 0x8c, (byte) 0xa9, 0x67, 0x12, (byte) 0x82, (byte) 0xfa, (byte) 0xfb, 0x69, (byte) 0xda,
                (byte) 0x92, 0x72, (byte) 0x8b, 0x1a, 0x71, (byte) 0xde, 0x0a, (byte) 0x9e, 0x06, 0x0b, 0x29,
                0x05, (byte) 0xd6, (byte) 0xa5, (byte) 0xb6, 0x7e, (byte) 0xcd, 0x3b, 0x36, (byte) 0x92,
                (byte) 0xdd, (byte) 0xbd, 0x7f, 0x2d, 0x77, (byte) 0x8b, (byte) 0x8c, (byte) 0x98, 0x03,
                (byte) 0xae, (byte) 0xe3, 0x28, 0x09, 0x1b, 0x58, (byte) 0xfa, (byte) 0xb3, 0x24, (byte) 0xe4,
                (byte) 0xfa, (byte) 0xd6, 0x75, (byte) 0x94, 0x55, (byte) 0x85, (byte) 0x80, (byte) 0x8b, 0x48,
                0x31, (byte) 0xd7, (byte) 0xbc, 0x3f, (byte) 0xf4, (byte) 0xde, (byte) 0xf0, (byte) 0x8e, 0x4b,
                0x7a, (byte) 0x9d, (byte) 0xe5, 0x76, (byte) 0xd2, 0x65, (byte) 0x86, (byte) 0xce, (byte) 0xc6,
                0x4b, 0x61, 0x16
        };
        final byte[] expectedTag = new byte[]{
                0x1a, (byte) 0xe1, 0x0b, 0x59, 0x4f, 0x09, (byte) 0xe2, 0x6a, 0x7e, (byte) 0x90, 0x2e,
                (byte) 0xcb, (byte) 0xd0, 0x60, 0x06, (byte) 0x91
        };

        byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);

        MemorySegment resultSegmentAlias;

        // 보안 스코프 내에서 암호화 연산 수행
        try (SDCScopeContext context = new SDCScopeContext()) {
            SensitiveDataContainer inputData = context.allocate(inputBytes, true);
            SensitiveDataContainer key = context.allocate(new byte[]{
                    (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
                    (byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b, (byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f,
                    (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
                    (byte) 0x98, (byte) 0x99, (byte) 0x9a, (byte) 0x9b, (byte) 0x9c, (byte) 0x9d, (byte) 0x9e, (byte) 0x9f
            }, true);
            SensitiveDataContainer nonce = context.allocate(new byte[]{
                    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
            }, true);
            SensitiveDataContainer aad = context.allocate(new byte[]{
                    0x50, 0x51, 0x52, 0x53, (byte) 0xc0, (byte) 0xc1, (byte) 0xc2, (byte) 0xc3, (byte) 0xc4, (byte) 0xc5, (byte) 0xc6, (byte) 0xc7
            }, true);
            SensitiveDataContainer result = ChaCha20.encrypt(context, key, nonce, aad, inputData);

            assertNotNull(result, "연산 결과는 null일 수 없습니다.");
            resultSegmentAlias = result.getMemorySegment();

            // [검증 A] 길이 검증
            assertEquals(expected.length + 16, resultSegmentAlias.byteSize(),
                    "암호문 길이가 불일치합니다.");

            // [검증 B] 무결성 검증 (correctness check)
            byte[] actualCipherBytes = resultSegmentAlias.toArray(ValueLayout.JAVA_BYTE); // 프로덕션에서 사용 권장 X
            assertEquals(actualCipherBytes.length, expected.length + 16, "암호문 길이가 불일치합니다.");
            byte[] newACBytes = new byte[actualCipherBytes.length - 16];
            System.arraycopy(actualCipherBytes, 0, newACBytes, 0, actualCipherBytes.length - 16);
            assertEquals(Hex.toHexString(expected), Hex.toHexString(newACBytes),
                    "암호문이 불일치합니다.");
            newACBytes = new byte[16];
            System.arraycopy(actualCipherBytes, actualCipherBytes.length - 16, newACBytes, 0, 16);
            assertEquals(Hex.toHexString(expectedTag), Hex.toHexString(newACBytes),
                    "MAC 태그가 불일치합니다.");

            //
            // 복호화
            //
            SensitiveDataContainer decryptResult = ChaCha20.decrypt(context, key, nonce, aad, result);
            MemorySegment decResultOpt = decryptResult.getMemorySegment();
            assertNotEquals(MemorySegment.NULL, decResultOpt, "네이티브 측 복호화 결과가 null입니다.");
            assertNotEquals(0, decResultOpt.address(), "네이티브 측 복호화 결과가 유효하지 않습니다.");
            byte[] actualDecBytes = decResultOpt.toArray(ValueLayout.JAVA_BYTE); // 프로덕션에서 사용 권장 X
            byte[] newADCBytes = new byte[actualDecBytes.length];
            System.arraycopy(actualDecBytes, 0, newADCBytes, 0, actualDecBytes.length);
            assertEquals(Hex.toHexString(inputBytes), Hex.toHexString(newADCBytes), "복호화 결과가 불일치합니다.");
        } // 스코프 벗어남 -> 컨텍스트 내부 모든 데이터 소거 요청 -> Rust에서 소거

        assertThrows(IllegalStateException.class, () ->
                        resultSegmentAlias.get(ValueLayout.JAVA_BYTE, 0),
                "스코프가 종료된 이후 메모리 세그먼트에 접근할 경우 반드시 예외가 발생하여 잔류 데이터 유출을 막아야 합니다.");
    }
}