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
@Fork(value = 1, jvmArgs = {
        "--enable-native-access=ALL-UNNAMED",
        "--enable-preview",
        "-Xms4g", "-Xmx4g" // 메모리 안정성 확보
})
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class NativeAVXCallBenchmark {

    private static final Linker LINKER = Linker.nativeLinker();

    private static final MethodHandle FFM_AVX_PROCESS_VECTOR;
    private static final MethodHandle FFM_AVX_POLY_ADD;

    // 벤치마킹 파라미터
    private static final long VECTOR_SIZE = 1024; // 1KB
    private static final int POLY_LEN = 256;      // 다항식 차수
    private static final int MODULUS_Q = 12289;   // LWE 모듈러스

    private Arena arena;
    private MemorySegment dataSegment;  // 벡터 연산용
    private MemorySegment polyASegment; // 다항식 A
    private MemorySegment polyBSegment; // 다항식 B

    static {
        final String commonNLN = "native_benchmark";
        System.loadLibrary(commonNLN);

        final String libName = System.mapLibraryName(commonNLN);
        Path lib = Path.of(System.getenv("ENTLIB_NATIVE_BIN"), libName).toAbsolutePath();
        if (Files.notExists(lib))
            throw new Error("네이티브 라이브러리 '" + libName + "'을(를) 찾을 수 없습니다!");
        SymbolLookup lookup = SymbolLookup.loaderLookup();

        // AVX 벡터 처리 함수
        FFM_AVX_PROCESS_VECTOR = LINKER.downcallHandle(
                lookup.find("process_vector_avx2").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_BYTE
                ),
                Linker.Option.critical(false)
        );

        // AVX 다항식 가산 함수
        FFM_AVX_POLY_ADD = LINKER.downcallHandle(
                lookup.find("poly_add_avx2").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT
                ),
                Linker.Option.critical(false)
        );
    }

    @Setup
    public void setup() {
        this.arena = Arena.ofConfined();

        // AVX-256(32바이트) 및 AVX-512(64바이트) 성능을 위해 64바이트 정렬
        long alignment = 64;

        // 벡터 연산용 메모리 할당
        this.dataSegment = arena.allocate(
                MemoryLayout.sequenceLayout(VECTOR_SIZE, ValueLayout.JAVA_BYTE)
                        .withByteAlignment(alignment)
        );

        // 다항식 연산용 메모리 할당 (i32 * 256)
        MemoryLayout polyLayout = MemoryLayout.sequenceLayout(POLY_LEN, ValueLayout.JAVA_INT)
                .withByteAlignment(alignment);
        this.polyASegment = arena.allocate(polyLayout);
        this.polyBSegment = arena.allocate(polyLayout);

        // 초기 데이터 로드 (Warmup 시 JVM 최적화 돕기 위함)
        for (long i = 0; i < VECTOR_SIZE; i++) {
            dataSegment.set(ValueLayout.JAVA_BYTE, i, (byte) i);
        }
        // 다항식 데이터 초기화
        for (int i = 0; i < POLY_LEN; i++) {
            polyASegment.setAtIndex(ValueLayout.JAVA_INT, i, i * 10);
            polyBSegment.setAtIndex(ValueLayout.JAVA_INT, i, i * 5);
        }
    }

    @TearDown
    public void tearDown() {
        arena.close();
    }

    /**
     * AVX2 최적화된 벡터 XOR 연산 (Zero-copy)
     * 예상 성능: 300ns ~ 500ns
     */
    @Benchmark
    public long invoke_avxProcessSecureVector() throws Throwable {
        FFM_AVX_PROCESS_VECTOR.invokeExact(dataSegment, VECTOR_SIZE, (byte) 0xAF);
        return dataSegment.get(ValueLayout.JAVA_BYTE, 0);
    }

    /**
     * AVX2 최적화된 다항식 모듈러 덧셈 (Branchless)
     * 예상 성능: 500ns ~ 800ns
     */
    @Benchmark
    public long invoke_avxPolyModularAdd() throws Throwable {
        FFM_AVX_POLY_ADD.invokeExact(polyASegment, polyBSegment, (long) POLY_LEN, MODULUS_Q);
        return polyASegment.get(ValueLayout.JAVA_INT, 0);
    }

    // avx2으아앙ㄱ
}