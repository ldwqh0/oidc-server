/*
 * This file was generated by the Gradle 'init' task.
 *
 * This project uses @Incubating APIs which are subject to change.
 */

plugins {
  id("org.xzcode.oidc.java-conventions")
}

dependencies {
  implementation(project(":oidc-server-core"))
  implementation(project(":oidc-server-configuration"))
}

description = "oidc-server-spring-boot-starter"
