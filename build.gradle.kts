/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

plugins {
    id("java")
    id("com.vanniktech.maven.publish") version "0.28.0"
    id("me.champeau.jmh") version "0.7.3"
}

val commonGroupId = project.findProperty("commonGroupId") as? String ?: "space.qu4nt"
val quantPublicDir = project.findProperty("quantPublicDir") as? String
    ?: layout.buildDirectory.dir("dummy-resources").get().asFile.absolutePath

val lombokVersion = "org.projectlombok:lombok:1.18.42"
val bouncyCastleVer = "1.83"

val entLibVersion = "1.1.2-Alpha3"

group = commonGroupId
version = entLibVersion

sourceSets {
    main {
        java {
            srcDirs("src/main/java")
        }
        resources {
            srcDirs("src/main/resources")

            if (quantPublicDir.isNotEmpty()) {
                val extraResourceDir = File("${quantPublicDir}/entanglementlib")
                if (extraResourceDir.exists()) {
                    srcDir(extraResourceDir)
                } else {
                    logger.warn("Warning: External resource directory not found: $extraResourceDir. Skipping...")
                }
            }
        }
    }

    test {
        java {
            srcDirs("src/test/java")
        }
        resources {
            srcDirs("src/test/resources")

            if (quantPublicDir.isNotEmpty()) {
                val extraTestResourceDir = File("${quantPublicDir}/entanglementlib-test")
                if (extraTestResourceDir.exists()) {
                    srcDir(extraTestResourceDir)
                }
            }
        }
    }

    named("jmh") {
        java {
            srcDirs("src/benchmark/java")
        }
        resources {
            srcDirs("src/benchmark/resources")
        }
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
    sourceCompatibility = JavaVersion.VERSION_25
    targetCompatibility = JavaVersion.VERSION_25
}

repositories {
    mavenCentral()
}

dependencies {
    // Quant-regular
    implementation("space.qu4nt.quant-regular:annotations:1.0.0")

    // JetBrains Annotations
    // https://mvnrepository.com/artifact/org.jetbrains/annotations
    implementation("org.jetbrains:annotations:26.0.2-1")

    // Logging
    // https://mvnrepository.com/artifact/org.slf4j/slf4j-api
    implementation("org.slf4j:slf4j-api:2.0.17")
    // bridger
    // https://mvnrepository.com/artifact/org.slf4j/jul-to-slf4j
    implementation("org.slf4j:jul-to-slf4j:2.0.17")
    // Logging Provider (Logback)
    // https://mvnrepository.com/artifact/ch.qos.logback/logback-classic
    implementation("ch.qos.logback:logback-classic:1.5.26")

    // Lombok
    // https://mvnrepository.com/artifact/org.projectlombok/lombok
    implementation(lombokVersion)
    annotationProcessor(lombokVersion)

    // https://mvnrepository.com/artifact/org.yaml/snakeyaml
    implementation("org.yaml:snakeyaml:2.5")

    // Jackson
    // https://mvnrepository.com/artifact/tools.jackson.core/jackson-databind
    implementation("tools.jackson.core:jackson-databind:3.0.2")
    // https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-annotations
    implementation("com.fasterxml.jackson.core:jackson-annotations:3.0-rc5")

    // BouncyCastle
    implementation("org.bouncycastle:bcprov-jdk18on:${bouncyCastleVer}")
    implementation("org.bouncycastle:bcutil-jdk18on:${bouncyCastleVer}")
    implementation("org.bouncycastle:bcpkix-jdk18on:${bouncyCastleVer}")
    implementation("org.bouncycastle:bctls-jdk18on:${bouncyCastleVer}")

    // Tests JUnit 5
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testAnnotationProcessor(lombokVersion)

    // JMH
    jmh("org.openjdk.jmh:jmh-core:1.37")
    jmh("org.openjdk.jmh:jmh-generator-annprocess:1.37")
    // Source: https://mvnrepository.com/artifact/org.openjdk.jmh/jmh-core
    testImplementation("org.openjdk.jmh:jmh-core:1.37")
    // Source: https://mvnrepository.com/artifact/org.openjdk.jmh/jmh-generator-annprocess
    testImplementation("org.openjdk.jmh:jmh-generator-annprocess:1.37")
    jmhAnnotationProcessor(lombokVersion)
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    from("entlib-native/dist") {
        into("native")
        include("linux/libentlib_native_aarch64.so", "linux/libentlib_native_x86_64.so",
            "macos/libentlib_native_aarch64.dylib", "macos/libentlib_native_universal.dylib", "macos/libentlib_native_x86_64.dylib",
            "windows/entlib_native_x86_64.dll")
    }
}

tasks.withType<Copy> {
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
}

mavenPublishing {
    signAllPublications()

    coordinates("${commonGroupId}.${project.name}", project.name, entLibVersion)

    pom {
        name = project.name
        description = "Quant EntanglementLib"
        inceptionYear = "2025"
        url = "https://github.com/Quant-Off/entanglementlib"

        licenses {
            license {
                name = "PolyForm Noncommercial License 1.0.0"
                url = "https://polyformproject.org/licenses/noncommercial/1.0.0/"
            }
        }

        developers {
            developer {
                id = "qtfelix"
                name = "Q. T. Felix"
                url = "https://github.com/Quant-TheodoreFelix"
            }
        }

        scm {
            url = "https://github.com/Quant-Off/entanglementlib"
            connection = "scm:git:git://github.com/Quant-Off/entanglementlib.git"
            developerConnection = "scm:git:ssh://git@github.com/Quant-Off/entanglementlib.git"
        }
    }

    configure(
        com.vanniktech.maven.publish.JavaLibrary(
            sourcesJar = true,
            javadocJar = com.vanniktech.maven.publish.JavadocJar.Javadoc()
        )
    )
}

//
// JMH - start
//
jmh {
    jmhVersion.set("1.37")

    // 테스트 벤치마킹 클래스 등록
    includeTests.set(true)
    includes.set(listOf(".*_JMHBenchmark"))

    // 벤치마크 실행 시 필요한 jvm 인자 중앙 제어
    jvmArgs.set(listOf(
        "--enable-native-access=ALL-UNNAMED",
        "--enable-preview",
        "-Djava.library.path=${projectDir}/native-benchmark/target/debug",
        "-Xms2g", "-Xmx2g" // gc 간섭 최소화
    ))
    fork.set(1)

    // 결과 출력 포맷
    resultFormat.set("JSON")

    // 벤치마크 수행 옵션 (프로세스 및 반복 횟수)
    fork.set(1)
    warmupIterations.set(3)
    iterations.set(5)
}
//
// JMH - end
//