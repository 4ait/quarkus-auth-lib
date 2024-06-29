import org.jreleaser.model.Active

group = "ru.code4a"
version = file("version").readText().trim()

plugins {
  kotlin("jvm") version "2.0.0"
  kotlin("plugin.serialization") version "2.0.0"

  id("org.kordamp.gradle.jandex") version "1.0.0"

  `java-library`
  `maven-publish`
  id("org.jreleaser") version "1.12.0"
}

java {
  withJavadocJar()
  withSourcesJar()
}

publishing {
  publications {
    create<MavenPublication>("mavenJava") {
      artifactId = "quarkus-auth"

      from(components["java"])

      pom {
        name = "Quarkus Session Authorization Library"
        description =
          "This library provides utilities for user authorization and session management. It utilizes dependency injection with Quarkus and includes several key classes for handling user authorization, session creation, and token encryption."
        url = "https://github.com/4ait/quarkus-auth-lib"
        inceptionYear = "2024"
        licenses {
          license {
            name = "The Apache License, Version 2.0"
            url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
          }
        }
        developers {
          developer {
            id = "tikara"
            name = "Evgeniy Simonenko"
            email = "tiikara93@gmail.com"
          }
        }
        scm {
          connection = "scm:git:git://github.com:4ait/quarkus-auth-lib.git"
          developerConnection = "scm:git:ssh://github.com:4ait/quarkus-auth-lib.git"
          url = "https://github.com/4ait/quarkus-auth-lib"
        }
      }
    }
  }
  repositories {
    maven {
      url =
        layout.buildDirectory
          .dir("staging-deploy")
          .get()
          .asFile
          .toURI()
    }
  }
}

repositories {
  mavenCentral()
}

tasks.withType<Test> {
  useJUnitPlatform()
  dependsOn(tasks["jandex"])
}

dependencies {
  implementation("io.quarkus:quarkus-arc:3.12.0")
  // implementation("jakarta.enterprise:jakarta.enterprise.cdi-api:4.1.0")
  // implementation("org.eclipse.microprofile.config:microprofile-config-api:3.1")

  implementation("com.lambdaworks:scrypt:1.4.0")
  implementation("ru.code4a:error-handling:1.0.0")

  testImplementation(kotlin("test"))
  testImplementation("org.mockito:mockito-core:5.12.0")
}

tasks.named("compileTestKotlin", org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask::class.java) {
  compilerOptions {
    freeCompilerArgs.add("-Xdebug")
  }
}

jreleaser {
  project {
    copyright.set("Company 4A")
  }
  gitRootSearch.set(true)
  signing {
    active.set(Active.ALWAYS)
    armored.set(true)
  }
  release {
    github {
      overwrite.set(true)
      branch.set("master")
    }
  }
  deploy {
    maven {
      mavenCentral {
        create("maven-central") {
          active.set(Active.ALWAYS)
          url.set("https://central.sonatype.com/api/v1/publisher")
          stagingRepositories.add("build/staging-deploy")
          retryDelay.set(30)
        }
      }
    }
  }
}
