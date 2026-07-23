plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("kotlin-kapt")
}

android {
    namespace = "com.skhoron.vault"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.skhoron.vault"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // --- Compose UI ---
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // --- Крипто: Argon2id + XChaCha20-Poly1305, чистый JVM (без NDK) ---
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // --- Локальное шифрованное хранилище ---
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    kapt("androidx.room:room-compiler:2.6.1")
    implementation("net.zetetic:sqlcipher-android:4.17.0")
    implementation("androidx.sqlite:sqlite:2.6.2")

    // --- Автозаполнение / биометрия ---
    implementation("androidx.biometric:biometric:1.1.0")

    // --- Локальное хранение соли/настроек, зашифрованное Android Keystore ---
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // --- Auto-lock: реакция на уход приложения в фон ---
    implementation("androidx.lifecycle:lifecycle-process:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.2")

    // ВНИМАНИЕ: намеренно НЕТ retrofit/okhttp/ktor и любых сетевых зависимостей.
    // Это architectural invariant проекта — см. README.md, раздел "Zero Network".
}
