group = "com.github.OpenEDGN.Security4K"

buildscript {
    repositories {
        mavenLocal()
        mavenCentral()
        maven { url = project.uri("https://jitpack.io") }
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.4.10")
    }
}

allprojects {
    repositories {
        mavenLocal()
        mavenCentral()
        maven { url = project.uri("https://jitpack.io") }
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
    for (childProject in childProjects.values) {
        delete(childProject.buildDir)
    }
}
