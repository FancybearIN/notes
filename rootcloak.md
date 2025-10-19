# What is RootCloak 

RootCloak is a category of techniques/tools that **hide evidence of a rooted device** from apps. The goal: make an app believe the device is _not_ rooted so it will enable or expose sensitive features it otherwise blocks. Think of it as a disguise for `su`, Magisk, and other root fingerprints.

**Short:** hide traces → app thinks “not rooted” → app enables guarded behavior.

# How it works (short, concrete)

Apps check a few things to decide “is rooted?” — root-hiding intercepts or modifies those signals:

1. **File checks**: app checks if `/system/bin/su` or similar exists → hide or fake `File.exists()` to return false.
    
2. **Command checks**: app runs `which su` or `su -c id` → intercept `Runtime.exec()` and return “not found”.
    
3. **Package checks**: app asks PackageManager for Magisk/SuperSU → filter those package names out.
    
4. **Props/env checks**: app reads `getprop` or env vars → spoof `ro.build.tags`, PATH, etc.
    
5. **Attestation**: app uses SafetyNet / Play Integrity → client-side hiding won’t help if server validates tokens.

Mechanisms to hide:

- **Magisk DenyList / systemless hiding** (for general, user-friendly hiding).
    
- **Xposed / LSPosed modules** (hook Java methods to change return values).
    
- **Frida scripts** (runtime hooking without needing Xposed; great for testing).
    
- **Repack/patch APK** (modify `isDeviceRooted()` to always `return false`).
    

Always perform these only on devices/targets you’re authorized to test.