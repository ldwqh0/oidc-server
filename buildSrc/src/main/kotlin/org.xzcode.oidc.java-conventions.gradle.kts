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
    mavenBom("org.springframework.boot:spring-boot-dependencies:2.6.3")
  }
}

java {
  withSourcesJar()
}

publishing {
  publications.create<MavenPublication>("maven") {
    from(components["java"])
    versionMapping {
      usage("java-api") {
        fromResolutionOf("runtimeClasspath")
      }
      usage("java-runtime") {
        fromResolutionResult()
      }
    }
  }
  repositories {
    maven {
      val releasesRepoUrl = "http://demo.yzhxh.com:8081/nexus/repository/maven-releases/"
      val snapshotsRepoUrl = "http://demo.yzhxh.com:8081/nexus/repository/maven-snapshots/"
      url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl)
      isAllowInsecureProtocol = true
      credentials {
        username = "lidong"
        password = "lidong"
      }
    }
    maven {
      val releasesRepoUrl = "https://packages.aliyun.com/maven/repository/2124183-release-zS40pt"
      val snapshotsRepoUrl = "https://packages.aliyun.com/maven/repository/2124183-snapshot-jg10er"
      url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl)
      isAllowInsecureProtocol = true
      credentials {
        username = "5f213c551d62073ceeb332b2"
        password = "NC=d3W)28)]W"
      }
    }
  }
}

tasks.withType<JavaCompile> {
  options.encoding = "UTF-8"
}
