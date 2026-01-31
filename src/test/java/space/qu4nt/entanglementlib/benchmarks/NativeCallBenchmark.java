/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.benchmarks;

import org.openjdk.jmh.annotations.*;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Thread)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED", "--enable-preview"})
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class NativeCallBenchmark {

    private static final Linker LINKER = Linker.nativeLinker();

    private static final MethodHandle FFM_ADD_HANDLE;
    private static final MethodHandle FFM_SECURE_VECTOR_HANDLE;
    private static final MethodHandle FFM_POLY_MODULAR_ADD;
    private static final MethodHandle FFM_SWAR_SECURE_VECTOR_HANDLE;
    private static final MethodHandle FFM_BLESS_POLY_MODULAR_ADD;

    // 벤치마킹을 위한 상수 정의
    private static final long VECTOR_SIZE = 1024; // 1KB 데이터
    private static final int POLY_LEN = 256;      // 다항식 차수
    private static final int MODULUS_Q = 12289;   // LWE 모듈러스

    private Arena arena;
    private MemorySegment dataSegment;
    private MemorySegment polyASegment;
    private MemorySegment polyBSegment;

    static {
        final String commonNLN = "native_benchmark";
        // jni
        System.loadLibrary(commonNLN);

        // ffm api
        final String libName = System.mapLibraryName(commonNLN);
        Path lib = Path.of(System.getenv("ENTLIB_NATIVE_BIN"), libName).toAbsolutePath();
        if (Files.notExists(lib))
            throw new Error("네이티브 라이브러리 '" + libName + "'을(를) 찾을 수 없습니다!");
        SymbolLookup lookup = SymbolLookup.loaderLookup();
        MemorySegment symbol = lookup.find("bench_add_numbers").orElseThrow();

        // Linker.Option.isTrivial() 추가로 오버헤드 최소화
        // 일반 사칙연산 함수
        FFM_ADD_HANDLE = LINKER.downcallHandle(
                symbol,
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG),
                Linker.Option.critical(false)
        );



        // 보안 벡터 처리 함수
        FFM_SECURE_VECTOR_HANDLE = LINKER.downcallHandle(
                lookup.find("process_secure_vector").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_BYTE),
                Linker.Option.critical(false)
        );
        // SWAR 도입된 보안 벡터 처리 함수
        FFM_SWAR_SECURE_VECTOR_HANDLE = LINKER.downcallHandle(
                lookup.find("swar_process_secure_vector").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_BYTE),
                Linker.Option.critical(false)
        );



        // 다항식 모듈러 가산 함수
        FFM_POLY_MODULAR_ADD = LINKER.downcallHandle(
                lookup.find("poly_modular_add").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT),
                Linker.Option.critical(false)
        );
        // 분기 없는 연산 도입 다항식 모듈러 가산 함수
        FFM_BLESS_POLY_MODULAR_ADD = LINKER.downcallHandle(
                lookup.find("bless_poly_modular_add").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT),
                Linker.Option.critical(false)
        );
    }

    // jni 선언
    public native long jni_add_numbers(long a, long b);


    @Benchmark
    public long invokeJNI() {
        // 기존 jni 호출 방식 (jvm transition 오버헤드 발생)
        return jni_add_numbers(10L, 20L);
    }

    @Setup
    public void setup() {
        this.arena = Arena.ofConfined();

        // 64바이트 정렬을 위한 바이트 정렬 지정 (AVX-512 등 활용 시 유리)
        long alignment = 64;

        // 정렬된 메모리 할당
        this.dataSegment = arena.allocate(
                MemoryLayout.sequenceLayout(VECTOR_SIZE, ValueLayout.JAVA_BYTE).withByteAlignment(alignment)
        );

        // 다항식 데이터 역시 정렬
        this.polyASegment = arena.allocate(
                MemoryLayout.sequenceLayout(POLY_LEN, ValueLayout.JAVA_INT).withByteAlignment(alignment)
        );
        this.polyBSegment = arena.allocate(
                MemoryLayout.sequenceLayout(POLY_LEN, ValueLayout.JAVA_INT).withByteAlignment(alignment)
        );

        // 초기 데이터 로드 (데이터 소거 및 연산 검증용)
        for (long i = 0; i < VECTOR_SIZE; i++) {
            dataSegment.set(ValueLayout.JAVA_BYTE, i, (byte) (i % 256));
        }
    }

    @TearDown
    public void tearDown() {
        // 메모리 해제 및 안전한 자원 반납
        arena.close();
    }

    @Benchmark
    public long invoke_hard_processSecureVector() throws Throwable {
        // 네이티브 레이어의 XOR 마스킹 연산 호출
        // (ptr: dataSegment, len: 1024, key: 0xAF)
        FFM_SECURE_VECTOR_HANDLE.invokeExact(dataSegment, VECTOR_SIZE, (byte) 0xAF);

        // JIT 최적화에 의한 Dead Code Elimination 방지를 위해 결과값 일부 반환
        return dataSegment.get(ValueLayout.JAVA_BYTE, 0);
    }

    @Benchmark
    public long invoke_hard_swarProcessSecureVector() throws Throwable {
        // 네이티브 레이어의 XOR 마스킹 연산 호출
        // (ptr: dataSegment, len: 1024, key: 0xAF)
        FFM_SWAR_SECURE_VECTOR_HANDLE.invokeExact(dataSegment, VECTOR_SIZE, (byte) 0xAF);

        // JIT 최적화에 의한 Dead Code Elimination 방지를 위해 결과값 일부 반환
        return dataSegment.get(ValueLayout.JAVA_BYTE, 0);
    }

    @Benchmark
    public long invoke_hard_polyModularAdd() throws Throwable {
        // 격자 기반 암호 연산의 핵심인 다항식 가산 시뮬레이션
        FFM_POLY_MODULAR_ADD.invokeExact(polyASegment, polyBSegment, (long) POLY_LEN, MODULUS_Q);

        return polyASegment.get(ValueLayout.JAVA_INT, 0);
    }

    @Benchmark
    public long invoke_hard_blessPolyModularAdd() throws Throwable {
        // 격자 기반 암호 연산의 핵심인 다항식 가산 시뮬레이션
        FFM_BLESS_POLY_MODULAR_ADD.invokeExact(polyASegment, polyBSegment, (long) POLY_LEN, MODULUS_Q);

        return polyASegment.get(ValueLayout.JAVA_INT, 0);
    }

    // 기존 단순 호출 벤치마크 (활성화 시 이전 결과와 비교 가능)
    @Benchmark
    public long invokeFFM_simple() throws Throwable {
        return (long) FFM_ADD_HANDLE.invokeExact(10L, 20L);
    }
}