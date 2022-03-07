plugins {
  `kotlin-dsl`
}
repositories {
  maven("https://maven.aliyun.com/repository/gradle-plugin")
  maven("https://plugins.gradle.org/m2/")
  mavenCentral()
}

dependencies {
  implementation("io.spring.gradle:dependency-management-plugin:1.0.11.RELEASE")
}
