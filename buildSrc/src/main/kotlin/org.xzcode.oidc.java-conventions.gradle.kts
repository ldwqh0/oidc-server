repositories {
  mavenCentral()
}
group = "org.xzcode.oidc"
version = "2.3.0-SNAPSHOT"

plugins {
  `java-library`
  `maven-publish`
}

java.sourceCompatibility = JavaVersion.VERSION_1_8
java.targetCompatibility = JavaVersion.VERSION_1_8

dependencies {
  implementation(platform("org.springframework.boot:spring-boot-dependencies:2.5.3"))
}

tasks.withType<JavaCompile> {
  options.encoding = "UTF-8"
}
