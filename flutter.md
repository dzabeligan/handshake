To import `.aar` files into your Flutter Android project, follow these detailed steps:

---

## ✅ Step-by-Step Guide:

### **1. Prepare your `.aar` file:**

Make sure you have your `.aar` file ready (e.g., `example_library.aar`).

---

### **2. Create a Directory for Your `.aar` file:**

In your Flutter project, navigate to:

```
your_flutter_project/android/
```

Then create a folder named `libs` if it doesn't already exist:

```
your_flutter_project/android/libs/
```

Place your `.aar` file into this directory.

Your project structure should now look like this:

```
your_flutter_project/
└── android/
    └── libs/
        └── example_library.aar
```

---

### **3. Update your Project-Level Gradle:**

Go to:

```
android/build.gradle
```

Ensure this repository block includes the `libs` folder:

```gradle
allprojects {
    repositories {
        google()
        mavenCentral()

        // Add this to include local .aar files
        flatDir {
            dirs 'libs'
            dirs project(':app').file('libs')
        }
    }
}
```

---

### **4. Update your App-Level Gradle:**

Navigate to:

```
android/app/build.gradle
```

Then, add your `.aar` file as a dependency:

```gradle
dependencies {
    implementation fileTree(dir: 'libs', include: ['*.aar', '*.jar'])
    // or specify explicitly:
    implementation(name: 'example_library', ext: 'aar')
}
```

Make sure to use the exact filename without the `.aar` extension.

---

### **5. Sync Gradle:**

Run these commands in your Flutter project root folder to sync your project:

```bash
cd android
./gradlew clean
./gradlew build
```

Alternatively, you can open your Android project separately in Android Studio (`File → Open → your_flutter_project/android`) and sync Gradle directly from the IDE.

---

### **6. Using Your `.aar` Library in Dart Code:**

Your `.aar` file (Android Archive) is a native Android library and can only be accessed via **Platform Channels** in Flutter.

To expose methods from the native `.aar` library to Flutter, follow these quick sub-steps:

**Step 6a:** Create a Platform Channel in Flutter:

```dart
import 'package:flutter/services.dart';

class ExampleLibrary {
  static const MethodChannel _channel =
      MethodChannel('com.example/example_library');

  static Future<String> getExampleData() async {
    final String result = await _channel.invokeMethod('getExampleData');
    return result;
  }
}
```

---

**Step 6b:** Implement Platform Channel on Android side:

In your Android code, edit:

```
android/app/src/main/kotlin/com/example/your_flutter_project/MainActivity.kt
```

Add this implementation to invoke the methods from your `.aar` file:

```kotlin
package com.example.your_flutter_project

import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import com.example.example_library.YourAarClass // Import from your .aar

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.example/example_library"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "getExampleData") {
                val exampleData = YourAarClass.getData() // Call your .aar function here
                result.success(exampleData)
            } else {
                result.notImplemented()
            }
        }
    }
}
```

Replace `YourAarClass` and `.getData()` with actual classes and methods from your `.aar` file.

---

## ✅ **Testing Your Setup:**

Run your Flutter app:

```bash
flutter run
```

Verify everything integrates smoothly and your native library is accessible.

---

**🎯 Summary of Key Steps:**

- Place `.aar` into `android/libs`.
- Add `flatDir` repository in project-level `build.gradle`.
- Add `.aar` dependency in app-level `build.gradle`.
- Use platform channels to expose `.aar` methods to Dart.

That's it! You've successfully integrated an `.aar` library into your Flutter Android project.
