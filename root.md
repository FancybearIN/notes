# What _is_ rooting?

Rooting is the process of gaining **superuser (root)** privileges on an Android device — basically getting the highest-level access to the operating system so you can do anything the OS normally prevents.

### Why apps care

Apps handling money, health data, or DRM-protected content often disable or restrict functionality on rooted devices because attacker-controlled root defeats local protections and lets adversaries extract secrets (tokens, keys, credentials).

Short practical note: to check for root existence you might see a `su` binary at `/system/bin/su` or `/system/xbin/su`, or try `adb shell su -c id` — on an unrooted device this will fail or be denied.

# How apps detect rooting — quick, practical, and searchable in JADX

Nice — let’s yank this apart like a curious robot. Below I’ll show exactly what apps look for (Java/Kotlin and React Native), give you concrete code patterns to hunt in JADX GUI, point out where false positives hide, and finish with quick Frida/adb checks you can use to confirm behavior at runtime.

[ Way to find out using jadx gui.](jadx)
