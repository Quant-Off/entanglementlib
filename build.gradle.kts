/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

plugins {
    java
}

val entLibVersion = "2.0.0"

allprojects {
    group = "space.qu4nt.entanglementlib"
    version = entLibVersion
}

subprojects {
    apply(plugin = "java")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(26))
        }
        sourceCompatibility = JavaVersion.VERSION_26
        targetCompatibility = JavaVersion.VERSION_26
    }

    repositories {
        mavenCentral()
    }

    dependencies {
        // JetBrains Annotations
        // https://mvnrepository.com/artifact/org.jetbrains/annotations
        implementation("org.jetbrains:annotations:26.1.0")

        // Logging
        // https://mvnrepository.com/artifact/org.slf4j/slf4j-api
        implementation("org.slf4j:slf4j-api:2.0.17")
        // Logging Provider (Logback)
        // https://mvnrepository.com/artifact/ch.qos.logback/logback-classic
        implementation("ch.qos.logback:logback-classic:1.5.26")

        // Tests JUnit 5
        testImplementation(platform("org.junit:junit-bom:5.10.0"))
        testImplementation("org.junit.jupiter:junit-jupiter")
        testImplementation("org.assertj:assertj-core:3.27.7")
        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    }

    tasks.test {
        useJUnitPlatform()
    }

    tasks.withType<Copy> {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
}
