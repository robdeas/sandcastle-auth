import org.springframework.boot.gradle.tasks.bundling.BootJar

plugins {
    id("org.springframework.boot") version "3.1.2"
    id("io.spring.dependency-management") version "1.1.0"
    java
}

group = "tech.robd"
version = "0.0.1-SNAPSHOT"
java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")
    implementation("org.postgresql:postgresql")
    // For password encryption
    implementation("org.springframework.security:spring-security-crypto")
    // Add Spring Data REST dependency
    implementation("org.springframework.boot:spring-boot-starter-data-rest")
    implementation("org.springframework.boot:spring-boot-starter-logging")
    //    // H2 database for development, unfortunately implementation ("com.h2database:h2") would pollute prod version
//    implementation("org.springframework.boot:spring-boot-starter-data-jpa") {
//        exclude(group = "com.h2database", module = "h2")
//    }
//
//    // For development only
//    if (project.hasProperty("dev")) {
//        implementation("com.h2database:h2")
//    }
    implementation ("com.h2database:h2")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")
    implementation("com.fasterxml.jackson.core:jackson-databind")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<BootJar> {
    archiveBaseName.set("sandcastle-auth")
    archiveClassifier.set("exec")
}