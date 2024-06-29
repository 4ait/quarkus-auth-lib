
val quarkusPlatformGroupId: String by rootProject
val quarkusPlatformArtifactId: String by rootProject
val quarkusPlatformVersion: String by rootProject

group = "ru.code4a"
version = "1.0.0"

plugins {
  kotlin("jvm") version "2.0.0"
  kotlin("plugin.serialization") version "2.0.0"

  id("org.kordamp.gradle.jandex") version "1.0.0"

  `java-library`
  `maven-publish`
  id("org.jreleaser") version "1.12.0"
}

publishing {
  publications {
    create<MavenPublication>("mavenJava") {
      artifactId = "quarkus-auth"

      from(components["java"])

      pom {
        name = "Session Authorization Library"
        description =
          "This library provides utilities for user authorization and session management. It utilizes dependency injection with Quarkus and includes several key classes for handling user authorization, session creation, and token encryption."
        url = "https://github.com/4ait/kotlin-errorhandling-library"
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
          connection = "scm:git:git://github.com:4ait/kotlin-error-handling-library.git"
          developerConnection = "scm:git:ssh://github.com:4ait/kotlin-error-handling-library.git"
          url = "https://github.com/4ait/kotlin-error-handling-library"
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
}

dependencies {
  implementation(enforcedPlatform("$quarkusPlatformGroupId:$quarkusPlatformArtifactId:$quarkusPlatformVersion"))
  implementation("io.quarkus:quarkus-arc")

  implementation("com.lambdaworks:scrypt:1.4.0")
  implementation("ru.code4a:error-handling:1.0.0")

  testImplementation("io.quarkus:quarkus-junit5")
  testImplementation("io.quarkus:quarkus-junit5-mockito")
  testImplementation("io.rest-assured:rest-assured")
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

/**
 * Reason: Task ':libs:authorization:test' uses this output of task ':libs:authorization:jandex' without declaring an explicit or implicit dependency.
 * This can lead to incorrect results being produced, depending on what order the tasks are executed.
 *
 *     Possible solutions:
 *       1. Declare task ':libs:authorization:jandex' as an input of ':libs:authorization:test'.
 *       2. Declare an explicit dependency on ':libs:authorization:jandex' from ':libs:authorization:test' using Task#dependsOn.
 *       3. Declare an explicit dependency on ':libs:authorization:jandex' from ':libs:authorization:test' using Task#mustRunAfter.
 */
tasks.named("test") {
  // enabled = false
}
