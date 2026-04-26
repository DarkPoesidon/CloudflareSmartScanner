# Android Engine Wrapper

This is a simple native Android app scaffold using Kotlin + Gradle.

## Purpose
- Wraps a local Go engine `.aar` file from `app/libs/`
- Provides a minimal UI with a Start/Stop button and result display
- Uses reflection in `EngineBridge.kt` so the app can compile without knowing exact AAR class names at scaffold time

## Setup
1. Copy your `engine.aar` into `app/libs/`
2. Update `EngineBridge.kt` if necessary:
   - `ENGINE_CLASS_NAME`
   - method names: `start`, `stop`, `fetchResult`
3. Build the app with Gradle

## Build
On Windows, run:

```powershell
cd d:\cloudflare-site-scanner\workspace\app
gradle assembleDebug
```

If you want a wrapper, run `gradle wrapper` first to generate the wrapper files.
