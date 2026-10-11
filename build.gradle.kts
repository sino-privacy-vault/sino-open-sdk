plugins {
    kotlin("jvm") version "2.4.10"
    kotlin("plugin.serialization") version "2.4.10"
}

group = "com.sino"
version = "4.0.0"

repositories {
    mavenCentral()
    google()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")

    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.test {
    useJUnit()
}

// Self-contained recovery tool: `java -jar build/libs/sino-recovery-<version>.jar <command> ...`.
tasks.register<Jar>("recoveryJar") {
    group = "build"
    description = "Builds the standalone recovery CLI with its dependencies."
    archiveBaseName.set("sino-recovery")
    manifest { attributes["Main-Class"] = "com.sino.sdk.cli.SinoDecryptorCLI" }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({ configurations.runtimeClasspath.get().filter { it.name.endsWith(".jar") }.map { zipTree(it) } }) {
        // Dependency signatures do not survive repackaging.
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC", "META-INF/versions/*/module-info.class", "module-info.class")
    }
}
