# 1) Common root-detection techniques (what to expect)

Apps use a mix of **filesystem checks**, **process/su checks**, **command execution**, **environment/property checks**, **library checks**, and **attestation**.

Typical checks you'll see in decompiled code:

- File existence checks for binaries/paths:
    
    - `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`
        
    - `/system/app/Superuser.apk`, `/system/xbin/daemonsu`
        
- Trying to run `su` via `Runtime.exec()` or `ProcessBuilder`.
    
- Checking `which su` or `getprop` output (`ro.build.tags`, `ro.secure`).
    
- Checking for Magisk, SuperSU or known root management apps (`com.topjohnwu.magisk`, `eu.chainfire.supersu`).
    
- Checking for loaded native libraries or suspicious mount flags (`/system` remounted read-write).
    
- Using third-party libs: **RootBeer**, **libsu**, or custom `RootUtils`, `RootChecker`, `SafetyNet` wrappers.
    
- Debuggable flag or signature checks: `android:debuggable="true"` or mismatched signature.
    
- SafetyNet / Play Integrity API calls (attestation tokens sent to server).
    

---

# 2) Concrete code patterns to search for (Kotlin / Java)

Search for these patterns/identifiers in JADX (Ctrl+F), and look at the surrounding code:

File / path checks:

`new File("/system/bin/su").exists() new File("/system/xbin/su").exists() File f = new File("/su/bin/su"); if (f.exists()) ...`

Runtime exec:

`Runtime.getRuntime().exec("su"); Runtime.getRuntime().exec(new String[]{"which", "su"}); Process p = Runtime.getRuntime().exec("sh -c \"which su\"");`

ProcessBuilder:

`new ProcessBuilder("/system/xbin/su", "-c", "id").start();`

getprop / getenv:

`String tags = System.getProperty("ro.build.tags");  // sometimes via getprop String env = System.getenv("PATH");`

Third-party libs and helper method names:

`RootBeer rootBeer = new RootBeer(context); rootBeer.isRooted();  RootUtil.isDeviceRooted() SecurityChecks.isRooted() isDeviceRooted() checkSuBinary()`

Manifest / flags:

`<application android:debuggable="true" ... />`

Network/Attestation:

`SafetyNetClient.something... attestationResult, ctsProfileMatch, nonce, playIntegrity`

---

# 3) React Native specifics

React Native apps can detect root either in JS (limited) or via a native module (Java/Kotlin/Obj-C). So hunt both.

JS-level checks (limited, trivial):

`import { NativeModules } from 'react-native'; const { RootCheckModule } = NativeModules; RootCheckModule.isDeviceRooted((isRooted) => console.log(isRooted));`

Search for `NativeModules` references and module names like `RootCheck`, `RootDetector`, `isDeviceRooted`.

Native modules (Android) — look for:

- `ReactContextBaseJavaModule` classes exposing `isDeviceRooted`.
    
- Methods annotated with `@ReactMethod` returning root-check results.
    

Example Java native-module pattern:

`public class RootCheckerModule extends ReactContextBaseJavaModule {   @ReactMethod   public void isDeviceRooted(Promise promise) {     boolean rooted = RootUtils.isDeviceRooted();     promise.resolve(rooted);   } }`

So in JADX, search for `ReactContextBaseJavaModule`, `@ReactMethod`, or module registration strings (module names used in JS).

Also search `package.json` and `node_modules` strings (if the app bundled RN libraries) — sometimes library names like `react-native-root-check` appear in resources.

---

# 4) How to use JADX GUI effectively (step-by-step)

1. **Open APK**: File → Open → load the APK.
    
2. **Search everything**: Press `Ctrl+F` and search these batches of terms:
    
    - `su`, `magisk`, `superuser`, `RootBeer`, `isRooted`, `checkRoot`, `getprop`, `which su`, `Runtime.getRuntime().exec`, `ProcessBuilder`, `com.topjohnwu`, `com.noshufou`, `com.kingroot`, `com.koushikdutta.superuser`.
        
3. **Filter noise**: use `\b` or case-insensitive searches. Example regex search (JADX supports basic regex):
    
    `\b(isRooted|checkRoot|RootBeer|rootcloak|magisk|superuser|getprop|which\s+su|Runtime\.getRuntime\(\)\.exec)\b`
    
4. **Inspect classes**:
    
    - If you find `isDeviceRooted()` or `RootUtils.*`, click the class, read method implementation. Look for `File.exists()` or `exec()` inside.
        
5. **Resources & manifest**:
    
    - On the left, open `resources` → `AndroidManifest.xml` and `res/values/strings.xml` for user-visible warning strings.
        
    - Check manifest for `android:debuggable="true"` or suspicious exported components.
        
6. **Native libs**:
    
    - Check `lib/` for `.so` files. If present, search for `su` strings in those native libs via jadx (strings view) or `strings` CLI — native code may obfuscate but strings can leak.
        
7. **Network calls**:
    
    - Search for `attest`, `safetynet`, `playintegrity`, `nonce`, `ctsProfileMatch` to find attestation usage.
        
8. **React Native module hint**:
    
    - Search for `ReactContextBaseJavaModule`, `@ReactMethod`, `getName()` methods that register module names seen in JS.
        

---

# 5) Quick examples you can paste into JADX search

Use these exact queries (Ctrl+F) to find risk indicators:

- `new File("/system/bin/su").exists`
    
- `Runtime.getRuntime().exec("su")`
    
- `which su`
    
- `RootBeer`
    
- `isDeviceRooted`
    
- `checkRoot`
    
- `magisk`
    
- `com.topjohnwu.magisk`
    
- `SafetyNetClient`
    
- `attest`
    
- `playIntegrity`
    
- `@ReactMethod`
    
- `ReactContextBaseJavaModule`
    

---

# 6) False positives & caveats

- Apps may check `su` but only to show a warning — not necessarily gating sensitive features. Severity depends on what root gating protects.
    
- Some checks look for debuggable or emulator indicators for benign reasons (analytics, crash collection).
    
- Absence of `su` strings in code ≠ absence of detection — detection may be obfuscated, implemented in native code, or done server-side.
    
- Modern Magisk can hide `su` and some techniques; presence of checks doesn’t mean they’re effective.
    

---

# 7) Runtime confirmation (quick PoC techniques, if you have a test device)

- **adb logcat**: run `adb logcat` and press the app’s “CHECK ROOT” button; look for logs that show a root-detection decision.
    
- **Frida**: hook common methods to see calls in-flight:
    
    `// frida snippet - log Runtime.exec calls Java.perform(function () {   var Runtime = Java.use('java.lang.Runtime');   Runtime.exec.overload('java.lang.String').implementation = function (cmd) {     console.log('[Runtime.exec] ' + cmd);     return this.exec(cmd);   }; });`
    
- **Modify return values**: use Frida to force `isDeviceRooted()` → `false` and observe behavior.
    
- **ADB checks** (if you can access device):
     

    ```adb shell which su adb shell getprop ro.build.tags adb shell getenforce`
    
- **Network sniff**: proxy the app and see if it sends attestation tokens — presence means server-side checks may exist (but confirm if server validates them).
    

---

# 8) Short example: Kotlin root-check snippet to recognize in JADX
```

fun isDeviceRooted(): Boolean {
    val paths = arrayOf("/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su")
    for (path in paths) {
        if (File(path).exists()) return true
    }
    try {
        val p = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
        val `in` = BufferedReader(InputStreamReader(p.inputStream))
        if (`in`.readLine() != null) return true
    } catch (e: Exception) { }
    return false
}
```
``

If you see similar code in JADX — bingo.

---

# 9) Quick checklist for reporting (bug bounty)

- Where you found the detection code (class/method + bytecode path in JADX).
    
- Exact strings/methods (copy-paste lines).
    
- How you bypassed it (Frida script or repackaging) and what the app allowed after bypass (tokens, features).
    
- Business impact (what sensitive feature was gated).
    

---

# Final practical tip (one-liner cheat to run in JADX search)

Search this combined term (copy exactly):

`isRooted|isDeviceRooted|checkRoot|RootBeer|magisk|superuser|which su|Runtime.getRuntime().exec|ReactContextBaseJavaModule|@ReactMethod|SafetyNet|attest`
