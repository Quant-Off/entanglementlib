/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

plugins {
    id("java")
    id("com.vanniktech.maven.publish") version "0.28.0"
}

val lombokVersion = "org.projectlombok:lombok:1.18.42"
val quantPublicDir: String by project
val commonGroupId: String by project
val bouncyCastleVer = "1.83"

val entLibVersion = "1.1.0-Alpha"

group = commonGroupId
version = entLibVersion

sourceSets {
    main {
        resources {
            srcDirs += File("${quantPublicDir}/entanglementlib")
        }
    }
    test {
        resources {
            srcDirs += File("${quantPublicDir}/entanglementlib-test")
        }
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_24
    targetCompatibility = JavaVersion.VERSION_24
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
    implementation("ch.qos.logback:logback-classic:1.5.21")

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
    // 1.83 부터 SLH-DSA 알고리즘 TLS 지원
    implementation("org.bouncycastle:bctls-jdk18on:${bouncyCastleVer}")

    // Tests JUnit 5
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.6")
    testAnnotationProcessor(lombokVersion)

    // Mockito
    // Source: https://mvnrepository.com/artifact/org.mockito/mockito-core
    testImplementation("org.mockito:mockito-core:5.21.0")
}

tasks.test {
    useJUnitPlatform()
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
