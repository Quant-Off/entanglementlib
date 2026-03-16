package space.qu4nt.entanglementlib.security.crypto.hash;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.NativeLinker;
import space.qu4nt.entanglementlib.security.entlibnative.NativeComponent;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.util.stream.IntStream;

public final class Hash {

    public static SensitiveDataContainer sha2(
            final int length,
            @NotNull SDCScopeContext scope,
            @NotNull SensitiveDataContainer input
    ) throws Throwable {
        final int[] ableLens = {224, 256, 384, 512};
        if (IntStream.of(ableLens).noneMatch(l -> l == length))
            return null;

        // 길이에 맞는 함수 등록
        NativeComponent newContextFunc, updateFunc, finalizeFunc, freeFunc;
        switch (length) {
            case 224 -> {
                newContextFunc = NativeComponent.SHA2_224_New;
                updateFunc = NativeComponent.SHA2_224_Update;
                finalizeFunc = NativeComponent.SHA2_224_Finalize;
                freeFunc = NativeComponent.SHA2_224_Free;
            }
            case 256 -> {
                newContextFunc = NativeComponent.SHA2_256_New;
                updateFunc = NativeComponent.SHA2_256_Update;
                finalizeFunc = NativeComponent.SHA2_256_Finalize;
                freeFunc = NativeComponent.SHA2_256_Free;
            }
            case 384 -> {
                newContextFunc = NativeComponent.SHA2_384_New;
                updateFunc = NativeComponent.SHA2_384_Update;
                finalizeFunc = NativeComponent.SHA2_384_Finalize;
                freeFunc = NativeComponent.SHA2_384_Free;
            }
            case 512 -> {
                newContextFunc = NativeComponent.SHA2_512_New;
                updateFunc = NativeComponent.SHA2_512_Update;
                finalizeFunc = NativeComponent.SHA2_512_Finalize;
                freeFunc = NativeComponent.SHA2_512_Free;
            }
            default -> throw new ELIBSecurityProcessException("불가능한 길이");
        }

        // 컨텍스트 생성
        MemorySegment ctx = (MemorySegment) NativeLinker.call(newContextFunc).invokeExact();
        boolean isCtxConsumed = false; // double-free 방지를 위한 상태 플래그

        try {
            // 데이터 업데이트
            MethodHandle updateMH = NativeLinker.call(updateFunc);
            MemorySegment dataSeg = InternalNativeBridge.unwrapMemorySegment(input);
            int status = (int) updateMH.invokeExact(ctx, dataSeg, dataSeg.byteSize());
            if (status != 0) {
                throw new ELIBSecurityProcessException("업데이트 실패, 상태 코드: " + status);
            }

            // 연산 수행 -> SecureBuffer* 반환 (ctx 소유권 소비됨)
            MemorySegment secureBufferPtr = (MemorySegment) NativeLinker.call(finalizeFunc)
                    .invokeExact(ctx);
            isCtxConsumed = true; // 성공적으로 finalize 되었으므로 플래그 전환

            if (secureBufferPtr.equals(MemorySegment.NULL))
                throw new ELIBSecurityProcessException("해시 연산 결과가 null입니다!");

            return NativeLinker.transferNativeBufferBindToContext(
                    scope, secureBufferPtr
            ); // 이 작업 내에서 버퍼 소거가 진행됨
        } finally {
            // 예외 발생 등으로 인해 finalize가 호출되지 않은 경우에만 early free
            if (!isCtxConsumed && ctx != null && !ctx.equals(MemorySegment.NULL)) {
                NativeLinker.call(freeFunc).invokeExact(ctx);
            }
        }
    }

    public static SensitiveDataContainer sha3(
            final int length,
            @NotNull SDCScopeContext scope,
            @NotNull SensitiveDataContainer input
    ) throws Throwable {
        final int[] ableLens = {224, 256, 384, 512};
        if (IntStream.of(ableLens).noneMatch(l -> l == length))
            return null;

        // 길이에 맞는 함수 등록
        NativeComponent newContextFunc, updateFunc, finalizeFunc, freeFunc;
        switch (length) {
            case 224 -> {
                newContextFunc = NativeComponent.SHA3_224_New;
                updateFunc = NativeComponent.SHA3_224_Update;
                finalizeFunc = NativeComponent.SHA3_224_Finalize;
                freeFunc = NativeComponent.SHA3_224_Free;
            }
            case 256 -> {
                newContextFunc = NativeComponent.SHA3_256_New;
                updateFunc = NativeComponent.SHA3_256_Update;
                finalizeFunc = NativeComponent.SHA3_256_Finalize;
                freeFunc = NativeComponent.SHA3_256_Free;
            }
            case 384 -> {
                newContextFunc = NativeComponent.SHA3_384_New;
                updateFunc = NativeComponent.SHA3_384_Update;
                finalizeFunc = NativeComponent.SHA3_384_Finalize;
                freeFunc = NativeComponent.SHA3_384_Free;
            }
            case 512 -> {
                newContextFunc = NativeComponent.SHA3_512_New;
                updateFunc = NativeComponent.SHA3_512_Update;
                finalizeFunc = NativeComponent.SHA3_512_Finalize;
                freeFunc = NativeComponent.SHA3_512_Free;
            }
            default -> throw new ELIBSecurityProcessException("불가능한 길이");
        }

        // 컨텍스트 생성
        MemorySegment ctx = (MemorySegment) NativeLinker.call(newContextFunc).invokeExact();
        boolean isCtxConsumed = false; // double-free 방지를 위한 상태 플래그

        try {
            // 데이터 업데이트
            MethodHandle updateMH = NativeLinker.call(updateFunc);
            MemorySegment dataSeg = InternalNativeBridge.unwrapMemorySegment(input);
            int status = (int) updateMH.invokeExact(ctx, dataSeg, dataSeg.byteSize());
            if (status != 0) {
                throw new ELIBSecurityProcessException("업데이트 실패, 상태 코드: " + status);
            }

            // 연산 수행 -> SecureBuffer* 반환 (ctx 소유권 소비됨)
            MemorySegment secureBufferPtr = (MemorySegment) NativeLinker.call(finalizeFunc)
                    .invokeExact(ctx);
            isCtxConsumed = true; // 성공적으로 finalize 되었으므로 플래그 전환

            if (secureBufferPtr.equals(MemorySegment.NULL))
                throw new ELIBSecurityProcessException("해시 연산 결과가 null입니다!");

            return NativeLinker.transferNativeBufferBindToContext(
                    scope, secureBufferPtr
            ); // 이 작업 내에서 버퍼 소거가 진행됨
        } finally {
            // 예외 발생 등으로 인해 finalize가 호출되지 않은 경우에만 early free
            if (!isCtxConsumed && ctx != null && !ctx.equals(MemorySegment.NULL)) {
                NativeLinker.call(freeFunc).invokeExact(ctx);
            }
        }
    }

    public static SensitiveDataContainer sha3Shake(
            final int length,
            final long byteOutLen,
            @NotNull SDCScopeContext scope,
            @NotNull SensitiveDataContainer input
    ) throws Throwable {
        final int[] ableLens = {128, 256};
        if (IntStream.of(ableLens).noneMatch(l -> l == length))
            return null;

        // 길이에 맞는 함수 등록
        NativeComponent newContextFunc, updateFunc, finalizeFunc, freeFunc;
        switch (length) {
            case 128 -> {
                newContextFunc = NativeComponent.SHA3_SHAKE128_New;
                updateFunc = NativeComponent.SHA3_SHAKE128_Update;
                finalizeFunc = NativeComponent.SHA3_SHAKE128_Finalize;
                freeFunc = NativeComponent.SHA3_SHAKE128_Free;
            }
            case 256 -> {
                newContextFunc = NativeComponent.SHA3_SHAKE256_New;
                updateFunc = NativeComponent.SHA3_SHAKE256_Update;
                finalizeFunc = NativeComponent.SHA3_SHAKE256_Finalize;
                freeFunc = NativeComponent.SHA3_SHAKE256_Free;
            }
            default -> throw new ELIBSecurityProcessException("불가능한 길이");
        }

        // 컨텍스트 생성
        MemorySegment ctx = (MemorySegment) NativeLinker.call(newContextFunc).invokeExact();
        boolean isCtxConsumed = false; // double-free 방지를 위한 상태 플래그

        try {
            // 데이터 업데이트
            MethodHandle updateMH = NativeLinker.call(updateFunc);
            MemorySegment dataSeg = InternalNativeBridge.unwrapMemorySegment(input);
            int status = (int) updateMH.invokeExact(ctx, dataSeg, dataSeg.byteSize());
            if (status != 0) {
                throw new ELIBSecurityProcessException("업데이트 실패, 상태 코드: " + status);
            }

            // 연산 수행 -> SecureBuffer* 반환 (ctx 소유권 소비됨)
            MemorySegment secureBufferPtr = (MemorySegment) NativeLinker.call(finalizeFunc)
                    .invokeExact(ctx, byteOutLen);
            isCtxConsumed = true; // 성공적으로 finalize 되었으므로 플래그 전환

            if (secureBufferPtr.equals(MemorySegment.NULL))
                throw new ELIBSecurityProcessException("해시 연산 결과가 null입니다.");

            return NativeLinker.transferNativeBufferBindToContext(
                    scope, secureBufferPtr
            ); // 이 작업 내에서 버퍼 소거가 진행됨
        } finally {
            // 예외 발생 등으로 인해 finalize가 호출되지 않은 경우에만 early free
            if (!isCtxConsumed && ctx != null && !ctx.equals(MemorySegment.NULL)) {
                NativeLinker.call(freeFunc).invokeExact(ctx);
            }
        }
    }
}