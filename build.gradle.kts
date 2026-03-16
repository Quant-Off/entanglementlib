/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

plugins {
    java
    id("com.vanniktech.maven.publish") version "0.28.0"
}

val commonGroupId = project.findProperty("commonGroupId") as? String ?: "space.qu4nt"
val quantPublicDir = project.findProperty("quantPublicDir") as? String
    ?: layout.buildDirectory.dir("dummy-resources").get().asFile.absolutePath

val lombokVersion = "org.projectlombok:lombok:1.18.42"

val entLibVersion = "1.1.2"

allprojects {
    group = "{$commonGroupId}.entanglementlib"
    version = entLibVersion
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "com.vanniktech.maven.publish")

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
        // JetBrains Annotations
        // https://mvnrepository.com/artifact/org.jetbrains/annotations
        implementation("org.jetbrains:annotations:26.0.2-1")

        // Logging
        // https://mvnrepository.com/artifact/org.slf4j/slf4j-api
        implementation("org.slf4j:slf4j-api:2.0.17")
        // Logging Provider (Logback)
        // https://mvnrepository.com/artifact/ch.qos.logback/logback-classic
        implementation("ch.qos.logback:logback-classic:1.5.26")

        // Lombok
        // https://mvnrepository.com/artifact/org.projectlombok/lombok
        implementation(lombokVersion)
        annotationProcessor(lombokVersion)

        // Tests JUnit 5
        testImplementation(platform("org.junit:junit-bom:5.10.0"))
        testImplementation("org.junit.jupiter:junit-jupiter")
        testImplementation("org.assertj:assertj-core:3.27.7")
        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
        testAnnotationProcessor(lombokVersion)
    }

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

    tasks.test {
        useJUnitPlatform()
    }

    tasks.withType<Copy> {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }

    tasks.named<Jar>("sourcesJar") {
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }
}