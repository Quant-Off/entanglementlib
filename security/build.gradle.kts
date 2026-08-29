plugins {
    id("me.champeau.jmh") version "0.7.3"
}

dependencies {
    implementation(project(":core"))
    implementation(project(":annotations"))

    // BouncyCastle FIPS (CryptoBackend.BOUNCY_CASTLE_FIPS 백엔드 전용)
    // 에어갭 배포에서 BC 미포함 선택지를 남기기 위해 compileOnly 로 둔다
    // https://mvnrepository.com/artifact/org.bouncycastle/bc-fips
    compileOnly("org.bouncycastle:bc-fips:2.1.2")
    testImplementation("org.bouncycastle:bc-fips:2.1.2")

    // JMH
//    jmh("org.openjdk.jmh:jmh-core:1.37")
//    jmh("org.openjdk.jmh:jmh-generator-annprocess:1.37")
//    // Source: https://mvnrepository.com/artifact/org.openjdk.jmh/jmh-core
//    testImplementation("org.openjdk.jmh:jmh-core:1.37")
//    // Source: https://mvnrepository.com/artifact/org.openjdk.jmh/jmh-generator-annprocess
//    testImplementation("org.openjdk.jmh:jmh-generator-annprocess:1.37")
}

//sourceSets {
//    named("jmh") {
//        java {
//            srcDirs("src/benchmark/java")
//        }
//        resources {
//            srcDirs("src/benchmark/resources")
//        }
//    }
//}

tasks.jar {
    from("../entlib-native/dist") {
        into("native")
        include(
            "linux/libentlib_native_aarch64.so",
            "linux/libentlib_native_x86_64.so",
            "macos/libentlib_native_aarch64.dylib",
            "macos/libentlib_native_universal.dylib",
            "macos/libentlib_native_x86_64.dylib",
            "windows/entlib_native_x86_64.dll"
        )
    }
}

//
// JMH - start
//
//jmh {
//    jmhVersion.set("1.37")
//
//    // 테스트 벤치마킹 클래스 등록
//    includeTests.set(true)
//    includes.set(listOf(".*_JMHBenchmark"))
//
//    // 벤치마크 실행 시 필요한 jvm 인자 중앙 제어
//    jvmArgs.set(listOf(
//        "--enable-native-access=ALL-UNNAMED",
//        "--enable-preview",
//        "-Djava.library.path=${rootDir}/native-benchmark/target/debug",
//        "-Xms2g", "-Xmx2g" // gc 간섭 최소화
//    ))
//    fork.set(1)
//
//    // 결과 출력 포맷
//    resultFormat.set("JSON")
//
//    // 벤치마크 수행 옵션 (프로세스 및 반복 횟수)
//    fork.set(1)
//    warmupIterations.set(3)
//    iterations.set(5)
//}
//
// JMH - end
//