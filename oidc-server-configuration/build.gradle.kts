plugins {
  id("org.xzcode.oidc.java-conventions")
}

dependencies {
  implementation("org.springframework.boot:spring-boot-configuration-processor")
  implementation("org.springframework.boot:spring-boot-autoconfigure")
  implementation("org.springframework.security:spring-security-web")
  implementation("org.springframework.security:spring-security-config")
  implementation("org.springframework.security:spring-security-oauth2-resource-server")
  implementation("org.springframework.security:spring-security-oauth2-jose")
  implementation("org.apache.commons:commons-lang3")
  implementation(project(":oidc-server-core"))

  compileOnly("jakarta.servlet:jakarta.servlet-api")
}
