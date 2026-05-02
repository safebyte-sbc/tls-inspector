import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    kotlin("jvm") version "2.1.0"
    id("com.gradleup.shadow") version "9.0.0-beta4"
}

group = "io.safebyte.tlsinspector"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API — provided at runtime by Burp itself
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.12")

    // minimal-json — tiny (33 KB) JSON parser for resource files + crt.sh responses.
    // Avoids Jackson + its transitive kotlin-reflect + bytebuddy (~14 MB combined).
    implementation("com.eclipsesource.minimal-json:minimal-json:0.9.5")

    // BouncyCastle 1.79 — TLS handshake control + X.509 parsing.
    // Relocated to avoid clash with Burp's bundled BC provider.
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bctls-jdk18on:1.79")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")

    // dnsjava — CAA DNS record lookups (RFC 8659)
    implementation("dnsjava:dnsjava:3.6.2")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

configurations.all {
    resolutionStrategy {
        force("org.bouncycastle:bcprov-jdk18on:1.79")
        force("org.bouncycastle:bctls-jdk18on:1.79")
        force("org.bouncycastle:bcpkix-jdk18on:1.79")
    }
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    // Burp 2024+ ships with JRE 21. Compile with toolchain 17 for broadest
    // compatibility but require at least 17 to run.
    jvmToolchain(21)
}

tasks.withType<ShadowJar> {
    archiveClassifier.set("")
    archiveBaseName.set("tls-inspector")
    mergeServiceFiles()

    // Relocate BouncyCastle to a private namespace so we never clash with
    // anything Burp (or another extension) brings to the classpath.
    relocate("org.bouncycastle", "io.safebyte.tlsinspector.shadow.bouncycastle")

    manifest {
        attributes(
            "Implementation-Title"   to "TLS Inspector",
            "Implementation-Version" to project.version
        )
    }
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
