plugins {
  id("org.xzcode.oidc.java-conventions")
}

dependencies {
  implementation("org.springframework:spring-web")
  implementation("org.springframework:spring-webmvc")
  implementation("org.springframework.security:spring-security-oauth2-core")
  implementation("org.springframework.security:spring-security-oauth2-resource-server")
  implementation("org.springframework.security:spring-security-oauth2-jose")
  implementation("org.apache.commons:commons-lang3")
  implementation("com.fasterxml.jackson.core:jackson-databind")
  implementation("jakarta.validation:jakarta.validation-api")
  implementation("org.slf4j:slf4j-api")
  implementation("commons-codec:commons-codec")

  compileOnly("jakarta.servlet:jakarta.servlet-api")
  compileOnly("org.springframework:spring-tx")
  testImplementation("org.junit.jupiter:junit-jupiter-api")
  testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
}
