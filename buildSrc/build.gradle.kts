plugins {
  `kotlin-dsl`
}
repositories {
  maven {
    url = uri("https://plugins.gradle.org/m2/")
  }
  mavenLocal()
  mavenCentral()
}

dependencies {
  implementation("io.spring.gradle:dependency-management-plugin:1.0.11.RELEASE")
}
