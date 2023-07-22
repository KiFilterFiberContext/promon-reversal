# Promon SHIELD Reversal
Overview of Promon SHIELD's Android application protection

## Disclaimer
The information provided is solely meant for educational purposes and is not intended to encourage malicious practice.  An existing publication on the protector already discusses many aspects mentioned in this repository.  This is intended to reveal some of the details behind **a few** mechanisms for two reasons:

1. There is not much information on existing Android anti-tamper solutions 
2. To compare the protection against other commercial application protectors
I do not delve too deep into the specifics of every mechanism used by the protector and only briefly mention pieces of information I found relevant during my time reverse engineering.  However, I do include proof-of-concept code of a bypass for the APK signature authentication to demonstrate that it is still possible to use the same techniques outlined by the publication from **2018**.  

Much credit is owed to the original researchers, as much of this work would not be possible without them.  Credit is also due to the developers that work at Promon as creating software to defend mobile applications is not an easy task and is quite impressive.  It is always fun to see how developers try to secure their applications because it always ends up fascinating to research!

## Backstory
While analyzing of my favorite games, Brawl Stars, peeking at decompressed APK revealed the following shared libraries in the `lib/arm64-v8a/` directory:
- `libg.so`
- `libsentry.so`
- `libsentry-android.so`
- `libfmod.so`

and finally...
- `libniiblkgocjbb.so`

The one that stands out here is `libniiblkgocjbb.so` (or rather `libshield.so`) as it is quite unusually large and the name is obviously conspicuous.  

As it turns out, this game is protected by [Promon SHIELD](https://promon.co/), a security solution that aims to safeguard applications from various threats from application repackaging to financial fraud.
This protector was formerly known primarily for being used by banking applications as mentioned by the publication so seeing it on a game like this was interesting.

In fact, Supercell has bundled the solution with all of their major mobile games at the time of writing.

Despite its impressive features, nothing is impenetrable (given enough time), so I decided to take a look at it myself with the aim of seeing if it was a worthy solution and to teach myself a thing or two.

## General Overview
Promon advertises its application shielding as self-protecting and resistant against static attacks:
> App shielding protects your application code and prevents your app from being reverse engineered, repackaged or decompiled. 

and dynamic attacks:

> With app shielding, your app is protected against malware, app tampering, emulators, debugging and hooking framework. App shielding protects your app in an untrusted environment and on jailbroken/rooted devices. 

## Technical Overview
### Java Obfuscation
Despite there being no obfuscation of the Dalvik bytecode, Promon SHIELD does use a neat trick to protect strings and class fields from being present in the decompiled Java.

Instead of strings being statically, the code will invoke a native method present only in the shield library by index.
```java
// snip
ApplicationUtil.requestAdvertiserInfoOnNewThread();
this.f9787m = getStringResourceByName(C6539Z.m1788a(4822));
if (this.f9789o != -1) {
    this.f9788n = getResources().getString(this.f9789o);
} else {
    String str3 = this.f9788n;
    String m1788a = C6539Z.m1788a(4823);
    if (str3 == null || str3.isEmpty() || this.f9788n.equals(m1788a)) {
        String stringResourceByName = getStringResourceByName(C6539Z.m1788a(4824));
        this.f9788n = stringResourceByName;
        if (stringResourceByName.isEmpty()) {
            this.f9788n = m1788a;
        }
    }
}
// snip
``` 
The class `C6539Z` contains two native methods registered dynamically by the shield library:
```java
public class C6539Z {
    /* renamed from: a */
    public static native String m1788a(int i);

    /* renamed from: a */
    public static native void m1787a(Class cls, int i);
}
```
These can be renamed to `getStringByID` and `initializeClassByID` respectfully.  As already mentioned by the publication, in order to prevent simple bypasses which simply replace or remove the existence of the shield library, the developers decided to use a binding between the Java code and the library so it is not possible to remove completely without extensive rewriting of the Dalvik bytecode.  

This is possible to do regardless as done by both the writers of the publication and the developers behind [Null's Brawl](https://nulls-brawl.com/), a popular private server for Brawl Stars that has removed the dependency from all Supercell games.

The method that loads the shield library uses XOR decryption to decrypt the library name:
```java
private static void m1739c() {
    char[] cArr = {(char) (cArr[6] ^ '\t'), (char) (cArr[0] ^ 7), (char) (cArr[6] ^ 14), (char) (cArr[0] ^ '\f'), (char) (cArr[7] ^ 3), (char) (cArr[4] ^ 7), (char) ((-5677) ^ (-5708)), (char) (cArr[0] ^ 1), (char) (cArr[6] ^ 4), (char) (cArr[6] ^ CharUtils.f16734CR), (char) (cArr[8] ^ 1), (char) (cArr[0] ^ '\f')};
    System.loadLibrary(new String(cArr).intern());
}
```
This form of string encryption is employed across the rest of the Java code in order to make analysis more difficult.

This does little when thwarting researchers but the real content lies within the native library.

### Static Code Obfuscation
When blindly opening the binary into a binary disassembler like IDA Pro or GHIDRA one will come to notice that the file is packed to no one's surprise.
Taking a look at the JNI entry point for native libraries (`JNI_OnLoad`) will yield *nothing* nor will looking at the entry point defined by the ELF header.  If both are packed along with the rest of the `.text` section, then where is the code?

Developers can define constructors and destructures for their shared library by using the `constructor` attribute.  Methods defined using this attribute will be executed prior to the entry point and the pointers to these methods stored in the `.init_array` section.  This is similar to how developers can define TLS callbacks to initialize thread-specific data prior to the PE entry point on Windows.

As expected, there is one function present in `.init_array`:
```assembly
.init_array:000000000052B8C8 off_52B8C8      DCQ sub_44321C          ; DATA XREF: LOAD:off_88↑o
.init_array:000000000052B8D0                 DCB    0
```
This function is responsible for dynamically retrieiving imports used by the library not visibly present in the Global Offset Table (GOT) and unpacking the rest of the binary using some crypto things that are explained in more detail by the CCC talk.  

The unpacked library will yield better results but the binary is obfuscated using a form of [control-flow obfuscation](https://news.sophos.com/en-us/2022/05/04/attacking-emotets-control-flow-flattening/).

Another form of "obfuscation" is the usage of direct system calls through the `SVC 0` instruction.  This can be used to call OS APIs that do not have to be imported from libc.
Aside from the imports defined by the ELF binary, there are several others that are imported dymically using `dlsym` or called directly using a system call instruction:
- `execl`
- `__system_property_get`
- `fork`
- `syscall`
- `killpg`
- `dladdr`
- `eventfd`
- `inotify_init`
- `prctl`
- `dl_iterate_phdr`
- `inotify_add_watch`
- `dlopen`
- `openat` (syscall)
- `ptrace` (syscall)
- `exit_group` (syscall)
- `kill` (syscall)
- `getpid` (syscall)
- `write` (syscall)
- `read` (syscall)
- `close` (syscall)
- `sigaction` (syscall)
- `mmap` (syscall)

and others.

There are also strings that are decrypted at runtime which can likely be extracted using something like [FLOSS](https://github.com/mandiant/flare-floss/) but I did not do this.
Now let us go over protection against dynamic attacks such as malware, app tampering, emulators, debugging and hooking frameworks.

### Anti-Debugging
The anti-debugging technique used by Linux applications to stop processes from attaching has [remained the same](https://github.com/yellowbyte/analysis-of-anti-analysis/blob/develop/research/hiding_call_to_ptrace/hiding_call_to_ptrace.md) for years, but it does include something neat.

The native anti-debugging mainly consists of the following:
1. call `prctl` with `PR_SET_DUMPABLE` and set it to true to allow the rest of the code to function properly
2. clone the process with `fork` 
3. the parent process calls `prctl` with `PR_SET_PTRACER` passing the child PID as the argument to restrict tracing to the child process
4. call `ptrace` using a system call with `PTRACE_ATTACH`, attaching to the parent process from the child
5. call `prctl` with `PR_SET_DUMPABLE` and set it to false to prevent core dumps and to **deny any process from attaching** to the child using `ptrace`

To prevent any Java debugging it will disable the functionality of the JDWP (Java Debug Wire Protocol) debugger inside of the Android Runtime (`libart.so`) by targeting the exported symbol: `art::JDWP::JdwpState::HandlePacket()`.

### APK Tampering
Most current methods of verifying APK integrity work by using [JNI reflection](https://blog.mikepenz.dev/a/protect-secrets-p3/).  

Promon SHIELD does not seem to do this, instead it directly opens the installed `base.apk` file using a system call to `openat` and parses the [APK signing block](https://source.android.com/docs/security/features/apksigning/v2) inside of the APK to extract the signing certificate.

It will also verify the checksum for the shield library, `libshield.so`, prior to proceeding with the rest of the checks.

### Emulator and Rooted Device Checks
There is no single way to detect an emulator or rooted device other than checking for a long list of file and device artifacts and that is precisely what is done. 

It will check the following set of device system properties for emulators and rooted devices:
- `ro.kernel.qemu`
- `ro.build.version.sdk`
- `ro.product.manufacturer`
- `ro.modversion`
- `persist.sys.root_access`
- `service.adb.root`
- `ro.debuggable`
- `ro.secure`
- `persist.sys.chromeos_channel`
- `ro.boot.chromeos_channel`
- `ro.product.device`
- `ro.product.model`
- `ro.product.vendor.model`
- `ro.hardware`
- `ro.product.cpu.abi`
- `persist.vmos.setting.show`
- `persist.vmos.tool.show`
- `ro.vmos.simplest.rom`
- `vmos.camera.enable`
- `ro.boot.serialno`
- `vmprop.wifissid`
- `ro.host.hardware.gralloc`
- `ro.build.tag`
- `ro.build.version.release`

You can likely determine which is for what purpose.

It also checks for a **VERY LONG** list of artifacts such as sudo binaries to determine if the device is rooted such as:
- `/system/xbin/su`
- `/data/local/sbin`
- `/bin/daemonsu`
- `/bin/su`
- `/data/adb/magisk/magisk`
- `/data/data-lib/com.kingroot.RushRoot`
- `/data/data-lib/com.kingroot.kinguser`
- `/data/data/com.kingoapp.apk`
- `/data/data/com.kingroot.kinguser`
- `/data/data/com.topjohnwu.magisk`
- `/data/data/eu.chainfire.supersu`
- `/dev/__properties__/u:object_r:supersu_prop:s0`
- `/data/user_de/0/com.kingroot.kinguser`
- `/init.supersu.rc`
- `/dev/com.koushikdutta.superuser.daemon/`
- `/system/addon.d/51-addonsu.sh`
- `/system/app/Superuser.apk`
- `/system/etc/init.d/99SuperSUDaemon`
- `/system/usr/we-need-root/su-backup`

and plenty of others...

It also inserts a filesystem watch for the following directories:
- `/bin`
- `/system/bin`
- `/system/xbin`
- `/vendor/bin`

### Anti-Hooking and Code Injection
Promon SHIELD primarily checks for three hooking frameworks on Android: Frida, XPosed, and Substrate.
It will check if any of the following libraries are mapped into the current process:
- `libsubstrate.so`
- `libsubstrate-dvm.so`
- `libxposed_art.so`
- `libFridaGadget.so`

Additional checks are performed on the ART to check if the following XPosed exports are present:
- `art::mirror::ArtMethod::EnableXposedHook(_JNIEnv*, _jobject*)`
- `art::ArtMethod::EnableXposedHook(art::ScopedObjectAccess&, _jobject*)`
- `art::mirror::ArtMethod::EnableXposedHook(art::ScopedObjectAccess&, _jobject*)`

There are also integrity checks done on the memory pages so any modifcation will lead to the process terminating itself.

## Credits
- [Honey, I Shrunk Your App Security: The State of Android App Hardening](https://obfuscator.re/nomorp-paper-dimva2018.pdf)
- [The fabulous world of mobile banking](https://media.ccc.de/v/34c3-8805-die_fabelhafte_welt_des_mobilebankings)
- [AArch64 Hooking Library](https://github.com/Rprop/And64InlineHook/tree/master)
