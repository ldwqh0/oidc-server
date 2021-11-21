repositories {
  mavenLocal()
  mavenCentral()
}
group = "org.xzcode.oidc"
version = "2.3.0-SNAPSHOT"

plugins {
  `java-library`
  `maven-publish`
  id("io.spring.dependency-management")
}

java.sourceCompatibility = JavaVersion.VERSION_1_8
java.targetCompatibility = JavaVersion.VERSION_1_8


dependencyManagement {
  imports {
    mavenBom("org.springframework.boot:spring-boot-dependencies:2.5.3")
  }
}

publishing {
  publications.create<MavenPublication>("maven") {
    from(components["java"])
  }
}

tasks.withType<JavaCompile> {
  options.encoding = "UTF-8"
}
