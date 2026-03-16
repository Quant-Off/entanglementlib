package space.qu4nt.entanglementlib.security.entlibnative;

import lombok.Getter;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;

@Getter
public class NativeProcessResult<A> {

    private final FFIStructEntLibResult<A> result;
    private final boolean success;
    private final byte typeId;
    private final byte statusCode;
    private final String message;
    private final @Nullable A additionalData;

    public NativeProcessResult(final FFIStructEntLibResult<A> result) {
        this.result = result;
        this.success = result.status() == 0;
        this.typeId = result.typeId();
        this.statusCode = result.status();
        this.message = message();
        this.additionalData = result.data();
    }

    private String message() {
        return MatchMessage.resolve(this.typeId, this.statusCode);
    }

    /// typeId(크레이트 식별자) + statusCode(결과 코드)를 메시지 문자열로 매핑하는 클래스입니다.
    ///
    /// 각 크레이트별 `status` 코드는 정적 초기화 블록에서
    /// [#register(byte, byte, String)]으로 등록합니다.
    ///
    /// - `status == 0`은 항상 성공으로 판단합니다.
    /// - `status != 0`은 할당 등록된 메시지를 반환합니다.
    ///
    /// @author Q. T. Felix
    /// @since 1.1.2
    private static final class MatchMessage {

        // Q. T. Felix TODO: 국제화 너무 힘들다...

        /**
         * key: typeId → (key: statusCode → message)
         */
        private static final Map<Byte, Map<Byte, String>> TABLE = new HashMap<>();

        // Q. T. Felix NOTE: 안티포렌식 관점에서 스테이터스 코드를 통해 오류를 정의하는 건 내부 상태를 유추할 수 있음을 뜻함.
        //                   이 기능은 수정될 수 있음.
        static {
            // entlib-native-secure-buffer
            register((byte) 0x00, (byte) -1, "외부로부터 받은 포인터가 null입니다!");

            // entlib-native-ffi (base64)
            register((byte) 0x01, (byte) -1, "FFI 입력 또는 출력 FFIStandard 포인터가 null입니다!");
            register((byte) 0x01, (byte) -2, "필요 버퍼 크기 산출 도중 산술 오버플로우가 발생했거나 OS 메모리 lock에 실패했습니다!");
            register((byte) 0x01, (byte) -3, "호출자가 할당한 출력 용량이 필요 크기(((input_len + 2) / 3) * 4)보다 작습니다!");
            register((byte) 0x01, (byte) -4, "호출자가 할당한 출력 용량이 최대 필요 크기((input_len / 4 + 1) * 3)보다 작습니다!");
            register((byte) 0x01, (byte) -5, "유효하지 않은 Base64 문자열(잘못된 길이/패딩/문자) 이거나 메모리 lock에 실패했습니다!");
            register((byte) 0x01, (byte) -1, "into_domain_buffer 함수 실행 결과가 유효하지 않습니다!");

            // entlib-native-ffi (hex)
            register((byte) 0x02, (byte) -1, "FFI 입력 또는 출력 FFIStandard 포인터가 null입니다!");

            // entlib-native-ffi (sha2)
            register((byte) 0x03, (byte) -1, "FFI 입력 또는 출력 FFIStandard 포인터가 null입니다!");

            // entlib-native-ffi (sha3, shake)
            register((byte) 0x04, (byte) -1, "FFI 입력 또는 출력 FFIStandard 포인터가 null입니다!");
        }

        /// 크레이트의 특정 상태 코드에 대한 메시지를 등록하는 메소드입니다.
        ///
        /// @param typeId  크레이트 식별자
        /// @param status  상태 코드 (음수)
        /// @param message 사람이 읽을 수 있는 메시지
        static void register(byte typeId, byte status, String message) {
            TABLE.computeIfAbsent(typeId, k -> new HashMap<>()).put(status, message);
        }

        /// 크레이트 + 상태 코드 조합으로 메시지를 조회하는 메소드입니다.
        ///
        /// @param typeId 크레이트 식별자
        /// @param status 상태 코드
        /// @return 매핑된 메시지, 또는 fallback 메시지
        static String resolve(byte typeId, byte status) {
            if (status == 0)
                return "OK";
            Map<Byte, String> statusMap = TABLE.get(typeId);
            if (statusMap == null)
                return "알 수 없는 크레이트 [typeId=0x" + String.format("%02X", typeId) + "]";
            return statusMap.getOrDefault(
                    status,
                    "정의되지 않은 에러 [typeId=0x" + String.format("%02X", typeId) + ", status=" + status + "]"
            );
        }
    }
}
