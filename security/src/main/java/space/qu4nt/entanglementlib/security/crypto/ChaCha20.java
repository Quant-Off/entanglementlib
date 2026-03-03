package space.qu4nt.entanglementlib.security.crypto;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.EntLibNativeManager;
import space.qu4nt.entanglementlib.security.entlibnative.Function;

import java.lang.foreign.MemorySegment;

@Slf4j
public final class ChaCha20 {

    private ChaCha20() {
        throw new UnsupportedOperationException("cannot access");
    }

    /// ChaCha20-Poly1305 암호화를 수행합니다.
    ///
    /// @param context     메모리 소거 생명주기를 관리하는 컨텍스트
    /// @param key       32바이트 대칭키 (호출 즉시 네이티브로 이전 후 소거됨)
    /// @param nonce     12바이트 Nonce (호출 즉시 네이티브로 이전 후 소거됨)
    /// @param aad       추가 인증 데이터 (선택 사항)
    /// @param plaintext 암호화할 평문 데이터 (호출 즉시 네이티브로 이전 후 소거됨)
    /// @return 암호화된 사이퍼텍스트(MAC 태그 포함)를 담은 SDC 객체
    public static @NotNull SensitiveDataContainer encrypt(
            final @NotNull SDCScopeContext context,
            final @NotNull SensitiveDataContainer key,
            final @NotNull SensitiveDataContainer nonce,
            final @Nullable SensitiveDataContainer aad,
            final @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException {

        try {
            // 입력 데이터를 SDC에 할당하여 네이티브 메모리로 이전 (forceWipe = true로 힙 메모리 즉시 소거)
            MemorySegment aadSegment = MemorySegment.NULL;
            long aadLen = 0;
            if (aad != null) {
                aadSegment = InternalNativeBridge.unwrapMemorySegment(aad);
                aadLen = InternalNativeBridge.unwrapMemorySegment(aad).byteSize();
            }

            // Rust FFI 호출 (Callee-allocated Opaque Pointer 반환)
            MemorySegment rustBufferPtr = (MemorySegment) EntLibNativeManager
                    .call(Function.ChaCha20_Poly1305_Encrypt)
                    .invokeExact(
                            InternalNativeBridge.unwrapMemorySegment(key), (long) InternalNativeBridge.unwrapMemorySegment(key).byteSize(),
                            InternalNativeBridge.unwrapMemorySegment(nonce), (long) InternalNativeBridge.unwrapMemorySegment(nonce).byteSize(),
                            aadSegment, aadLen,
                            InternalNativeBridge.unwrapMemorySegment(plaintext), (long) InternalNativeBridge.unwrapMemorySegment(plaintext).byteSize()
                    );

            if (rustBufferPtr.equals(MemorySegment.NULL)) {
                throw new ELIBSecurityProcessException("ChaCha20 암호화 실패: 유효하지 않은 입력 길이");
            }

            return EntLibNativeManager.transferNativeBufferBindToContext(
                    context, rustBufferPtr
            );
        } catch (Throwable t) {
            log.error("ChaCha20 암호화 중 치명적 보안 예외 발생", t);
            throw new ELIBSecurityProcessException("암호화 프로세스 실패", t);
        }
    }

    /// ChaCha20-Poly1305 복호화를 수행합니다.
    ///
    /// @return 복호화된 평문 데이터를 담은 SDC 객체
    public static @NotNull SensitiveDataContainer decrypt(
            final @NotNull SDCScopeContext context,
            final @NotNull SensitiveDataContainer key,
            final @NotNull SensitiveDataContainer nonce,
            final @Nullable SensitiveDataContainer aad,
            final @NotNull SensitiveDataContainer ciphertext) throws ELIBSecurityProcessException {

        try {
            MemorySegment aadSegment = MemorySegment.NULL;
            long aadLen = 0;
            if (aad != null) {
                aadSegment = InternalNativeBridge.unwrapMemorySegment(aad);
                aadLen = InternalNativeBridge.unwrapMemorySegment(aad).byteSize();
            }

            MemorySegment rustBufferPtr = (MemorySegment) EntLibNativeManager
                    .call(Function.ChaCha20_Poly1305_Decrypt)
                    .invokeExact(
                            InternalNativeBridge.unwrapMemorySegment(key), (long) InternalNativeBridge.unwrapMemorySegment(key).byteSize(),
                            InternalNativeBridge.unwrapMemorySegment(nonce), (long) InternalNativeBridge.unwrapMemorySegment(nonce).byteSize(),
                            aadSegment, aadLen,
                            InternalNativeBridge.unwrapMemorySegment(ciphertext), (long) InternalNativeBridge.unwrapMemorySegment(ciphertext).byteSize()
                    );

            // Authentication Failed 또는 입력 오류
            if (rustBufferPtr.equals(MemorySegment.NULL)) {
                throw new ELIBSecurityProcessException("ChaCha20 복호화 실패: 무결성 검증(MAC) 실패 또는 유효하지 않은 입력");
            }

            return EntLibNativeManager.transferNativeBufferBindToContext(
                    context, rustBufferPtr
            );
        } catch (Throwable t) {
            log.error("ChaCha20 복호화 중 치명적 보안 예외 발생", t);
            throw new ELIBSecurityProcessException("복호화 프로세스 실패", t);
        }
    }
}
