use jni::sys::*;
use std::arch::x86_64::{
    __m256i, _mm256_add_epi32, _mm256_and_si256, _mm256_cmpgt_epi32, _mm256_loadu_si256,
    _mm256_set1_epi32, _mm256_set1_epi8, _mm256_storeu_si256, _mm256_sub_epi32, _mm256_xor_si256,
};
use std::slice;

/// ffm api 단순 ++
#[unsafe(no_mangle)]
pub extern "C" fn bench_add_numbers(a: i64, b: i64) -> i64 {
    // jit 최적화 시 함수 자체가 제거되는 것을 방지하기 위해 최소한의 연산 수행
    a + b
}

/// 벡터의 XOR 연산 및 데이터 소거 시뮬레이션
/// 메모리 세그먼트에 직접 접근하여 연산을 수행하며, 데이터 보안을 위한 로직을 포함합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn process_secure_vector(ptr: *mut u8, len: usize, key: u8) {
    if ptr.is_null() {
        return;
    }

    // java의 memorysegment가 가리키는 주소를 슬라이스로 변환
    let data = slice::from_raw_parts_mut(ptr, len);

    for byte in data.iter_mut() {
        *byte ^= key; // 단순 xor 연산 (연산 복잡도 부여)
    }
}

/// SWAR(SIMD Within A Register) 도입
/// 1바이트씩 처리하는 대신, 64비트(8바이트) 단위로 처리하여 루프 반복 횟수를
/// 1/8로 줄여서 별도의 unsafe SIMD 인트린직 없이도 이식성 높은 고성능을 냅니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn swar_process_secure_vector(ptr: *mut u8, len: usize, key: u8) {
    if ptr.is_null() {
        return;
    }

    // 8바이트 단위 처리를 위한 정렬 확인 및 포인터 변환
    let mut offset = 0;

    // 8바이트 정렬 맞추기 전까지 처리
    while (ptr.add(offset) as usize) % 8 != 0 && offset < len {
        *ptr.add(offset) ^= key;
        offset += 1;
    }

    // 64비트(8바이트) 단위 고속 XOR (SWAR)
    // 1바이트 키를 8개 복제하여 64비트 마스크 생성 (e.g., 0xAF -> 0xAFAFAFAFAFAFAFAF)
    let key64 = u64::from_le_bytes([key; 8]);
    let ptr64 = ptr.add(offset) as *mut u64;
    let len64 = (len - offset) / 8;

    let data64 = slice::from_raw_parts_mut(ptr64, len64);

    // 루프 언롤링 힌트가 없어도, 단순 반복문은 컴파일러가 AVX/NEON으로 자동 변환하기 매우 쉽습니다.
    for chunk in data64.iter_mut() {
        *chunk ^= key64;
    }

    // 남은 자투리 바이트 처리
    offset += len64 * 8;
    while offset < len {
        *ptr.add(offset) ^= key;
        offset += 1;
    }
}

/// 격자 기반 암호용 다항식 모듈러 가산(modular addition)
/// LWE 계열 알고리즘의 핵심 연산을 시뮬레이션합니다.
/// 연산식: A[i] = (A[i] + B[i]) mod q
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poly_modular_add(a_ptr: *mut i32, b_ptr: *const i32, len: usize, q: i32) {
    if a_ptr.is_null() || b_ptr.is_null() {
        return;
    }

    let a = slice::from_raw_parts_mut(a_ptr, len);
    let b = slice::from_raw_parts(b_ptr, len);

    for i in 0..len {
        // 복잡한 조건문과 산술 연산을 통해 jit 최적화에 저항하고 실제 연산 부하 측정
        let sum = a[i] + b[i];
        a[i] = if sum >= q { sum - q } else { sum };
    }
}

/// Branchless 연산 수행
/// if 문은 CPU의 분기 예측 실패(branch misprediction)를 유발하여 파이프라인을 멈추게 합니다.
/// 이를 비트 연산이나 조건부 이동으로 대체합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bless_poly_modular_add(
    a_ptr: *mut i32,
    b_ptr: *const i32,
    len: usize,
    q: i32,
) {
    if a_ptr.is_null() || b_ptr.is_null() {
        return;
    }

    let a = slice::from_raw_parts_mut(a_ptr, len);
    let b = slice::from_raw_parts(b_ptr, len);

    // assert!(len % 4 == 0); // 가능하면 4의 배수로

    for i in 0..len {
        let sum = a[i] + b[i];

        // 분기 제거 최적화
        // sum >= q 이면 1, 아니면 0이 되는 값을 이용
        // Rust의 bool to integer 캐스팅은 최적화 시 분기 없는 코드로 변환됨
        let sub = (sum >= q) as i32 * q;

        a[i] = sum - sub;
    }
}

/// jni 단순 ++++
#[unsafe(no_mangle)]
#[unsafe(export_name = "Java_space_qu4nt_entanglementlib_benchmarks_NativeCallBenchmark_jni_1add_1numbers")]
pub extern "C" fn jni_add_numbers_impl(
    mut _env: JNIEnv,
    _class: jclass,
    a: jlong,
    b: jlong,
) -> jlong {
    a + b
}

//
// AVX - start
//

/// AVX2를 활용한 32바이트 단위 초고속 XOR (Zero-copy)
/// Target: invoke_hard_swarProcessSecureVector 대체
#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")] // 이 함수 내에서 AVX2 활성화
pub unsafe extern "C" fn process_vector_avx2(ptr: *mut u8, len: usize, key: u8) {
    if ptr.is_null() {
        return;
    }

    // 키 확장: 1바이트 키를 32바이트 벡터로 복제 (Broadcast)
    let key_vec = _mm256_set1_epi8(key as i8);

    let mut i = 0;
    // 256비트(32바이트) 단위 처리 (Loop Unrolling 포함 가능)
    // 1KB 기준 루프 횟수: 128회 -> 32회로 급감
    while i + 32 <= len {
        let p = ptr.add(i) as *mut __m256i;

        // Load (정렬되지 않은 데이터도 처리 가능한 lddqu 사용 권장되나, 최신 CPU는 loadu도 빠름)
        let data = _mm256_loadu_si256(p);

        // XOR 연산
        let xored = _mm256_xor_si256(data, key_vec);

        // Store
        _mm256_storeu_si256(p, xored);

        i += 32;
    }

    // 남은 자투리 바이트 처리 스칼라ㅏ라라라라라
    while i < len {
        *ptr.add(i) ^= key;
        i += 1;
    }
}

/// AVX2를 활용한 다항식 모듈러 가산 (Branchless & Vectorized)
/// Target: invoke_hard_blessPolyModularAdd 대체
#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub unsafe extern "C" fn poly_add_avx2(a_ptr: *mut i32, b_ptr: *const i32, len: usize, q: i32) {
    if a_ptr.is_null() || b_ptr.is_null() {
        return;
    }

    let q_vec = _mm256_set1_epi32(q);
    let mut i = 0;

    // 8개 정수(i32 * 8 = 256bit) 동시 처리
    while i + 8 <= len {
        let a_p = a_ptr.add(i) as *mut __m256i;
        let b_p = b_ptr.add(i) as *const __m256i;

        let a_val = _mm256_loadu_si256(a_p);
        let b_val = _mm256_loadu_si256(b_p);

        //  단순 덧셈: Res = A + B
        let sum = _mm256_add_epi32(a_val, b_val);

        // 모듈러 감산 로직 (Constant-time)
        // AVX2에는 부호 없는 비교가 없으므로 덧셈 후 MSB 체크 등의 기법 대신
        let q_minus_1 = _mm256_set1_epi32(q - 1);
        let mask = _mm256_cmpgt_epi32(sum, q_minus_1);

        // 빼야 할 값: q AND mask (mask가 0xFFFF...이면 q, 0이면 0)
        let sub = _mm256_and_si256(q_vec, mask);

        // 최종 감산: Res = Sum - Sub
        let res = _mm256_sub_epi32(sum, sub);

        _mm256_storeu_si256(a_p, res);

        i += 8;
    }

    // 남은 처리 (Scalar)
    while i < len {
        let sum = *a_ptr.add(i) + *b_ptr.add(i);
        *a_ptr.add(i) = if sum >= q { sum - q } else { sum };
        i += 1;
    }
}

//
// AVX - end
//
