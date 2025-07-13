# Binder/IPC framework

- Used to develop Object oriented OS services/environment that works on traditional Linux kernel.
- Not object oriented kernel
- Binder implements a distributed component architecture based on abstract interfaces.
### **1. Distributed Component Architecture**

- **Distributed**:  
    This means that the system consists of multiple processes (or components) that may run in **different memory spaces** or even on **different devices**. In Android, apps run in their own isolated processes, and system services (like the media server, location services, etc.) run separately as well.
    
- **Component Architecture**:  
    The system is made up of **modular components** (apps, services, daemons) that interact with each other. Think of each app or system service as a **component** that provides some functionality.

**Example**:  
When your app wants to play music, it doesn’t implement all the low-level audio functionality. Instead, it talks to the **MediaService** component, which runs in another process. The Binder framework handles the communication between these two components.
### **2. Abstract Interfaces**

- **Abstract Interfaces** define **how** components communicate without specifying the exact details of **what** each component does internally.
    
- In Android, this is typically done using **AIDL (Android Interface Definition Language)**, which allows you to define interfaces that different components can use to talk to each other, regardless of their internal implementations.
    
**Example**:  
You define an interface in AIDL like this:

```aidl
interface IExampleService {
    void performAction(int data);
}
```

When you call `performAction()` from your app, the Binder framework ensures that this call is **transparently routed** to the appropriate service, even if it's running in a completely different process.

### **Bringing It All Together**

**Binder implements a distributed component architecture based on abstract interfaces** means:

1. **Distributed Component Architecture**:  
    Android apps and system services are separate, independent processes (components) that need to communicate across process boundaries.
    
2. **Abstract Interfaces**:  
    Communication between these components is defined through standard interfaces (like AIDL), allowing different parts of the system to interact without worrying about internal implementations.
    
3. **Binder's Role**:  
    Binder handles the complex task of **marshalling** (packing) data, sending it to the right process, and **unmarshalling** (unpacking) it on the other side—all while maintaining security and efficiency.

**What is IPC?**
- Framework for exchange of signals and data across multiple process which is normally not possible due to process isolation
- Used for message passing, synchronization, shared memory, and remote procedure calls (RPC).
- Enables **information sharing**, computational speedup, **modularity**, convenience, **privilege separation**, **data isolation**, stability.
	- Each process has its own (sandboxed) address space, typically running under a unique system ID
## 1. **Binder Objects and Transactions**
- Each object accessed through the Binder framework implements the `IBinder` interface, called a **Binder Object**.
- Calls are performed inside a **Binder Transaction**, containing:
    - Reference to the target object
    - ID of the method to execute
    - Data buffer
        
- **Binder Driver** adds:
    - **Process ID (PID)**
    - **Effective User ID (EUID)** of the calling process
## 2. **Security Enforcement**

- **Callee (server process)** can inspect the PID and EUID to decide whether to execute the request.
- **Kernel-filled PID and EUID** prevent processes from faking their identity, avoiding privilege escalation.
- **Key API Methods:**
    - `getCallingPid()`
    - `getCallingUid()`

## 3. **Important Notes**

- **Multiple Apps under Same UID:**
    - The EUID may map to multiple apps, but security isn’t compromised as they share permissions.
    - SELinux rules can enforce process-specific restrictions.
        

## 4. **Binder Identity**

- Binder objects maintain a **unique identity** across processes.
- **Process References:**
    - **Process A:** Direct reference (memory address)
    - **Process B & C:** Handle references (kernel-managed)
    
- **Security Implications:**
    - Userspace processes can't duplicate or forge Binder objects.
    - Binder objects act as **unique, unforgeable security tokens**.
    
## 5. **Capability-Based Security Model**

- Access is granted via **unforgeable capabilities** that:
    - Reference the target object
    - Encapsulate access rights
        
- **No need for ACLs(Access Control Lists)** as possession of a capability implies access rights.
    
## 6. **Binder Tokens**
- **Binder Tokens** are Binder objects used as security capabilities.
- **Access Control:**
    - Full access granted if the process holds a Binder token.
    - For granular control, implement permission checks using PID and EUID.
        
## 7. **Common Access Control Patterns**

- **System UID (1000)** and **Root UID (0)** often have unrestricted access.
- Additional permission checks for other processes.
- **Dual-Layer Security:**
    - **Reference Limitation:** Restricting access to the Binder object.
    - **Caller Verification:** Permission checks during method execution.
        
## 8. **Binder Tokens as Capabilities**

- Can be used solely for authentication without extra functionality.
- **Usage Patterns:**
    - Similar to session cookies for client-server authentication.
    - **Internal Framework Use:** Often invisible to regular apps.
    - **Window Tokens:**
        - Manage application windows in Android.
        - Apps can access their own window tokens, but not others'.
        - Ensures secure window management, preventing unauthorized overlays.

## 9. **Accessing Binder Objects**
- **Binder Access Control**:
    - Android restricts access to Binder objects for security.
    - Communication with a Binder object requires a reference to it.
        
- **Need for Universal Access**:
    - Some Binder objects, especially system services, must be universally accessible.
    - It is impractical to distribute all service references to every process manually.
        
- **Service Discovery Mechanism**:
    - Android uses a **context manager** for service discovery.
    - The **servicemanager** native daemon acts as the context manager.
    - It is launched early in the boot process.
        
- **Service Registration**:
    - System services register themselves by providing:
        - A **service name**.
        - A **Binder reference**.
            
    - Once registered, any client can request the Binder reference using the service name.
        
- **Access Control and Permissions**:
    - Obtaining a Binder reference does **not guarantee full access**.
    - System services perform **additional permission checks**.
    - Only a **whitelisted** set of system processes can register system services.
    - Example: Only UID **1002 (AID_BLUETOOTH)** can register the **bluetooth** service.
        
- **Viewing Registered Services**:
    
    - Use the command:
        `service list`
        
    - This displays:
        - Name of each registered service.
        - Implemented `IBinder` interface.
            
- **Example Output (Android 4.4)**:
```
Found 79 services:
0   sip: [android.net.sip.ISipService]
1   phone: [com.android.internal.telephony.ITelephony]
2   iphonesubinfo: [com.android.internal.telephony.IPhoneSubInfo]
3   simphonebook: [com.android.internal.telephony.IIccPhoneBook]
4   isms: [com.android.internal.telephony.ISms]
5   nfc: [android.nfc.INfcAdapter]
6   media_router: [android.media.IMediaRouterService]
7   print: [android.print.IPrintManager]
8   assetatlas: [android.view.IAssetAtlas]
9   dreams: [android.service.dreams.IDreamManager]
...
```

# Android Framework Libraries
## Overview
- Also known simply as **“the framework”**.
- Comprises **Java libraries not included in the standard Java runtime** (`java.*`, `javax.*`, etc.).
- Primarily hosted under the `android.*` package hierarchy.
## Components
### Application Building Blocks
- **Base Classes for Android Components**:
  - Activities, Services, Content Providers
  - Located in `android.app.*`
### User Interface
- **GUI Widgets**:
  - Located in `android.view.*` and `android.widget.*`
### Data Access
- **File and Database Access**:
  - Located in `android.database.*` and `android.content.*`
### Hardware and System Services
- **Hardware Interaction** and **High-Level System Services Access**:
  - Provided through various specialized classes.
## System Services and Managers
- Most Android OS functionality (above the kernel) is implemented as **system services**.
- These services are not accessed directly.
- **Facade classes called "managers"** are used to interact with system services.
  - Example: `BluetoothManager` (facade) ↔ `BluetoothManagerService` (system service backend)

# Android App Types and Permissions

## System Apps
- **Location**: Preinstalled in the OS image (read-only, typically mounted as `/system`).
- **Security**: Cannot be uninstalled or modified by users.
- **Privileges**: Granted more privileges than user-installed apps.
- **Types**:
  - Core Android OS apps.
  - Preinstalled user applications (e.g., email clients, browsers).
- **Privileged Apps**:
  - From Android 4.4+, only apps in `/system/priv-app/` get **signatureOrSystem** level permissions.
  - Apps in `/system/` but not in `/priv-app/` do not receive these privileges.
- **Platform Key**:
  - Apps signed with the **platform signing key** can receive **signature** protection level permissions.
  - This allows non-system-path apps to get OS-level privileges.
- **Updates**:
  - Can be updated by user-installed versions if signed with the same private key.
  - Some system apps can be overridden (e.g., launcher, input method).

## User-Installed Apps
- **Location**: Installed in `/data`, a dedicated read-write partition.
- **Removability**: Can be uninstalled freely by the user.
- **Security Sandbox**: Each app runs in isolation.
- **Permissions**:
  - Can only access granted resources explicitly.
- **Security Principles**:
  - Follows **privilege separation**.
  - Enforces the **principle of least privilege**.

# Android App Components

## Overview
- Android apps consist of **loosely coupled components**.
- Apps can have **multiple entry points**, unlike traditional apps.
- Components respond to:
  - **User actions**
  - **System events**
  - **Other applications**

## AndroidManifest.xml
- Defines:
  - App components
  - Entry points
  - Metadata
  - **Package name** (unique identifier in reverse domain format, e.g., `com.google.email`)
- Compiled into **binary XML** before inclusion in the APK for performance and size optimization.
- Parsed at **install time** to register app components with the system.

## App Signing
- Each app must be **signed with the developer's key**.
- Prevents app replacement unless signed with the same key (updates allowed).

## Main Components

### 1. **Activities**
- Represents a **single screen** with a UI.
- Main building blocks of GUI apps.
- Multiple activities per app are allowed.
- Activities can be started independently, even by other apps (if permitted).

### 2. **Services**
- Background component with **no UI**.
- Used for **long-running tasks** (e.g., downloads, music).
- Can expose **remote interfaces** via AIDL.
- Unlike OS system services, app services are **started/stopped on demand**.

### 3. **Content Providers**
- Interface to **app data** (usually from a database or files).
- Used for **data sharing between apps**.
- Accessed via **Inter-Process Communication (IPC)**.
- Allows **fine-grained control** over shared data.

### 4. **Broadcast Receivers**
- Listens to **system-wide or app-originated events**.
- Examples:
  - System broadcast: network connectivity change.
  - App broadcast: background task completion.

# Android Security Model

## Overview: Leveraging Linux Kernel Security

*   **Foundation:** Android's security model is built upon the security features inherent in the Linux kernel.
*   **Linux as Multi-User:** The Linux kernel is designed as a multi-user OS, capable of isolating user resources and processes from one another.
    *   User file access is restricted by default (users cannot access other users' files without permission).
    *   Processes run with the identity (UID - User ID, GID - Group ID) of the user who started them.
    *   Exceptions exist via `SUID` (set-user-ID) and `SGID` (set-group-ID) bits on executables, allowing processes to run with different privileges (not the primary mechanism in Android app security).
*   **Android's Adaptation:** Android utilizes Linux user isolation but adapts the concept of a "user":
    *   **Traditional Linux:** UIDs represent distinct physical users or system daemons (services). This helps contain damage if a daemon is compromised.
    *   **Android (Original Design):** Primarily designed for single-user smartphones. The physical user is implicit.
    *   **Android's UID Usage:** UIDs are assigned to *applications* instead of physical users. This forms the core of Android's application sandboxing mechanism.

## Application Sandboxing

*   **Core Principle:** Isolate applications from each other at both the process and file system levels using Linux kernel mechanisms.
*   **Mechanism:**
    *   **Unique UID per App:** At installation time, Android assigns a unique Linux User ID (UID), often called an "app ID," to each application.
    *   **Dedicated Process:** Each application runs in its own process, executing under its assigned UID.
    *   **Dedicated Data Directory:** Each application is given a private data directory (e.g., `/data/data/<package_name>` on single-user devices).
        *   Ownership: This directory and its contents are owned by the application's unique UID.
        *   Permissions: By default, only the application's UID has read/write access to this directory.
    *   **Kernel-Level Enforcement:** This sandbox is enforced by the Linux kernel, making it robust and applicable to both native code and code running in virtual machines (like ART/Dalvik).
*   **UID Management:**
    *   **System vs. App UIDs:**
        *   System daemons and core applications run under predefined, constant UIDs. Very few run as `root` (UID 0).
        *   System UIDs are defined statically in `android_filesystem_config.h` (no traditional `/etc/password` file).
        *   System service UIDs start from 1000 (`AID_SYSTEM`), which has special but limited privileges.
        *   Application UIDs are generated automatically starting from 10000 (`AID_APP`).
    *   **Usernames:** Corresponding Linux usernames follow patterns like `app_XXX` or `uY_aXXX` (where `Y` is the Android *user* ID for multi-user devices, and `XXX` is the offset from `AID_APP`).
        *   Example: UID `10037` might correspond to username `u0_a37`.
    *   **Process Example (Listing 1-3):** `ps` output shows different applications (email, dialer, calendar) running as distinct users (`u0_a37`, `u0_a8`, `u0_a29`).
        ```bash
        $ ps # --snip--
        u0_a37    16973 182   941052  60800 ffffffff 400d073c S com.google.android.email
        u0_a8     18788 182   925864  50236 ffffffff 400d073c S com.google.android.dialer
        u0_a29    23128 182   875972  35120 ffffffff 400d073c S com.google.android.calendar
        u0_a34    23264 182   868424  31980 ffffffff 400d073c S com.google.android.deskclock # --snip--
        ```
    *   **Data Directory Example (Listing 1-4):** `ls -l` shows the application's data directory owned by its dedicated user (`u0_a37`).
        ```bash
        # ls -l /data/data/com.google.android.email
        drwxrwx--x u0_a37   u0_a37            app_webview
        drwxrwx--x u0_a37   u0_a37            cache
        drwxrwx--x u0_a37   u0_a37            databases
        drwxrwx--x u0_a37   u0_a37            files # --snip--
        ```
*   **Direct File Sharing (Discouraged):**
    *   Apps could historically use `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` flags to create files accessible by other apps (sets `S_IROTH` / `S_IWOTH` bits).
    *   This is discouraged and these flags are deprecated (since Android 4.2). Proper inter-component communication (IPC) mechanisms like Content Providers are preferred.
*   **UID Persistence and Tracking:**
    *   Application UIDs are managed alongside other package metadata.
    *   Canonical Source: `/data/system/packages.xml` (detailed in Chapter 3).
    *   Quick Reference: `/data/system/packages.list`.
    *   **`packages.list` Example (Listing 1-5):** Shows the mapping for `com.google.android.email`.
        ```bash
        # grep 'com.google.android.email' /data/system/packages.list
        com.google.android.email 10037 0 /data/data/com.google.android.email default 3003,1028,1015
        ```
        *   **Format:** `package_name UID debuggable_flag data_directory_path seinfo_label supplementary_GIDs`
        *   **Supplementary GIDs:** List of Group IDs assigned based on granted permissions. Each GID often corresponds to a specific permission.
*   **Shared User ID (`sharedUserId`):**
    *   **Concept:** Allows multiple applications to be assigned the *same* UID.
    *   **Benefits:**
        *   Can access each other's private data directories.
        *   Can optionally run within the same process.
    *   **Requirement:** Applications MUST be signed with the *exact same* code signing key.
    *   **Usage:** Primarily used by system applications for modularity (e.g., splitting functionality across packages while sharing resources).
    *   **System Example (Listing 1-6):** System UI (`com.android.systemui`) and Keyguard (`com.android.keyguard`) sharing UID `10012` in Android 4.4.
        ```bash
        # grep ' 10012 ' /data/system/packages.list
        com.android.keyguard 10012 0 /data/data/com.android.keyguard platform 1028,1015,1035,3002,3001
        com.android.systemui 10012 0 /data/data/com.android.systemui platform 1028,1015,1035,3002,3001
        ```
    *   **Third-Party Use:** Available but generally *not recommended* for non-system apps due to security implications and inflexibility.
    *   **Limitation:** A `sharedUserId` *cannot* be added to an existing application via an update, as this would change its UID, which is disallowed by the system. It must be declared from the application's initial release.

## Permissions

*   **Purpose:** Grant sandboxed applications specific, fine-grained access rights to resources *beyond* their own private data directory. Needed for richer functionality.
*   **Scope:** Control access to:
    *   Hardware devices (camera, GPS, sensors)
    *   Internet connectivity
    *   Other applications' data (e.g., contacts, calendar - often via Content Providers)
    *   OS services
*   **Declaration:** Applications request permissions by listing them in their `AndroidManifest.xml` file.
*   **Granting (Traditional Model):**
    *   The system inspects requested permissions at *install time*.
    *   Based on the permission's protection level and potentially user confirmation (for standard permissions in older models), the system decides whether to grant them.
    *   Once granted (in the traditional model described), permissions were generally persistent for the life of the installation and could not be easily revoked by the user (Note: This has changed significantly in Android 6.0+ with runtime permissions).
*   **Runtime Confirmation:** Even with a granted permission, accessing certain sensitive data (like specific private keys or user accounts) might require explicit user confirmation *at the time of access*. (See Chapters 7 & 8 for details).
*   **Restricted Permissions:**
    *   Some permissions are reserved for system applications (preinstalled or signed with the platform key).
*   **Custom Permissions:**
    *   Third-party applications can define their *own* custom permissions.
    *   They can assign *protection levels* to these custom permissions, restricting which other applications (e.g., only those signed by the same developer) can be granted access to the defining app's components or resources.
*   **Enforcement:** Permissions are enforced at different layers:
    *   **Kernel Level:** Access to low-level resources like device files (`/dev/*`) is checked by the Linux kernel based on the calling process's UID and GIDs compared against the resource's ownership and permission bits. Supplementary GIDs (from `packages.list`) play a role here, granting access based on group membership.
    *   **Framework/Component Level:** Access to higher-level Android components (Services, Content Providers, Broadcast Receivers, Activities) is typically enforced by the Android OS framework or sometimes by the component itself checking the caller's permissions. 

## IPC (Inter-Process Communication)

*   **Implementation:** Android IPC relies on a combination of:
    *   **Kernel Driver:** The Binder driver (`/dev/binder`).
    *   **Userspace Libraries:** Framework libraries that abstract Binder interactions.
*   **Binder's Security Role:**
    *   **Caller Identity Verification:** The Binder kernel driver provides a fundamental security guarantee: it reliably attaches the **UID (User ID)** and **PID (Process ID)** of the calling process to each IPC transaction.
    *   **Spoof-Proof:** This identity information *cannot be forged* by the calling process.
    *   **Foundation for Access Control:** Many system services leverage this guaranteed UID/PID to implement dynamic access control decisions.
*   **Dynamic Permission Checks (Runtime):**
    *   System services often check the caller's UID/PID *within* their method implementations to control access to sensitive APIs.
    *   They use methods like `Binder.getCallingUid()` and `Binder.getCallingPid()`.
    *   **Example (Listing 1-7):** The Bluetooth manager service checks if the caller's UID is `Process.SYSTEM_UID` (UID 1000) before allowing Bluetooth to be enabled silently (without user interaction). If the caller is not the system user or the foreground user, the request is denied.
        ```java
        public boolean enable() {
            if ((Binder.getCallingUid() != Process.SYSTEM_UID) &&
                (!checkIfCallerIsForegroundUser())) {
                Log.w(TAG,"enable(): not allowed for non-active and non-system user");
                return false;
             }
             // --snip--
        }
        ```
    *   This pattern is common across various system services for fine-grained control.
*   **Static Permission Checks (Manifest-based):**
    *   **Coarse-Grained Control:** Permissions can be required for *all* methods exposed by an IPC service (or other components like Activities, Receivers, Providers).
    *   **Declaration:** The *service provider* (callee) declares the required permission in its `AndroidManifest.xml` file using attributes like `android:permission`.
    *   **System Enforcement:** The Android system automatically enforces these permissions *before* dispatching the IPC call to the service method.
    *   **Underlying Mechanism:** This static check also relies on the caller UID provided by Binder.
    *   **Enforcement Steps:**
        1.  An IPC call targets a specific component (e.g., a Service).
        2.  The system looks up the component declaration (using the package database derived from `packages.xml`).
        3.  The system identifies the `android:permission` required by the target component (the callee).
        4.  The system obtains the caller's UID via the Binder transaction.
        5.  The system maps the caller's UID back to its package name(s).
        6.  The system retrieves the set of permissions that have been granted to the *caller* package (again, from the package database).
        7.  The system checks if the permission required by the callee is present in the set of permissions granted to the caller.
        8.  **If Granted:** The IPC call proceeds to the target component's method.
        9.  **If Not Granted:** The system blocks the call and throws a `SecurityException` back to the caller.
## Code Signing and Platform Keys

*   **Mandatory Signing:**
    *   Every Android application (APK), whether user-installed or part of the system, *must* be digitally signed by its developer. Unsigned APKs cannot be installed.
*   **Signing Mechanism:**
    *   Based on the standard Java JAR signing process, since APK files are essentially extended JAR files.
    *   Involves signing the application package with a developer's private key. The corresponding public key certificate is embedded in the APK.
*   **Primary Purposes of Code Signing:**
    1.  **Update Authenticity (Same Origin Policy):**
        *   Android uses the signature to verify that an update for an installed application comes from the *same original author*.
        *   When installing an update, the system compares the signature(s) of the currently installed APK with the signature(s) of the new APK.
        *   If the signatures do not match, the update is rejected. This prevents malicious actors from replacing legitimate apps with tampered versions.
    2.  **Establishing Trust Between Applications:**
        *   Signatures are used to determine if different applications originate from the same developer.
        *   This enables specific security features:
            *   **Shared User ID (`sharedUserId`):** Applications must be signed with the *exact same key* to share a UID and potentially resources/processes.
            *   **Signature-Level Permissions:** An application can define a custom permission with `protectionLevel="signature"`. Only other applications signed with the *same key* as the defining application can be granted this permission.
*   **Platform Keys:**
    *   A specific set of keys used to sign the core Android OS and pre-installed system applications.
    *   There can be one or *multiple* platform keys used within a single Android build.
    *   **Significance:** Applications signed with a platform key are granted special privileges:
        *   They can be granted highly sensitive "signature" or "signatureOrSystem" permissions defined by the OS.
        *   System components signed with the *same* platform key can share resources, use `sharedUserId`, and potentially run within the same process, facilitating tight integration.
*   **Control over Platform Keys:**
    *   The platform keys are generated, managed, and kept secret by the entity responsible for building and maintaining the specific Android version installed on a device. This could be:
        *   The device **Manufacturer** (OEM - e.g., Samsung, Xiaomi).
        *   The mobile **Carrier** (less common now, but historically some customized builds).
        *   **Google** (for its Pixel and historical Nexus devices).
        *   **End Users** or **Developers** who build custom Android versions from source code (e.g., AOSP-based custom ROMs).
    *   The security of the platform keys is critical to the integrity of the system apps and the OS itself.

## Multi-User Support

*   **Introduction:** Added in Android 4.2, primarily enabled on tablets (shared devices). Handsets often limited to 1 user.
*   **User Identification:** Each physical user is assigned a unique User ID (starting from 0).
*   **User-Specific System Data:** Each user gets a dedicated system directory: `/data/system/users/<user_id>/`. This stores user-specific settings, accounts, and installed app lists.
*   **Application Isolation:**
    *   **Shared Binaries:** Application APK files are shared among all users to save space.
    *   **Separate Data:** Each user gets a *separate copy* of an application's data directory.
    *   **Effective UID:** To maintain sandboxing between users for the *same* application, Android assigns a unique "effective UID" to each app instance *per user*. This UID is derived from a combination of the physical User ID and the application's base App ID.
    *   **Result:** Guarantees that an app installed by User 0 runs in a separate sandbox from the same app installed by User 1.
*   **Shared Storage:** Each user gets their own view of shared storage (like internal storage/SD card partitions), though it's generally world-readable within that user's context.
*   **Device Owner:** The first user set up on the device is designated the "owner". Only the owner can manage other user accounts and perform device-wide administrative tasks (e.g., factory reset).

## SELinux (Security Enhanced Linux)

*   **Motivation/Problem Addressed:**
    *   The traditional Android security model heavily relies on Linux User IDs (UIDs) and Group IDs (GIDs) – this is **Discretionary Access Control (DAC)**.
    *   **DAC Limitations:**
        *   Users/Applications control permissions on their own resources (files, etc.).
        *   An application can intentionally or accidentally grant overly broad access (e.g., world-readable/writable) to its private files.
        *   Malicious applications could potentially exploit overly permissive access controls on system files or local sockets.
        *   Inappropriate permissions have historically led to Android vulnerabilities.
        *   Under DAC, once access is granted, it can be passed on ("discretionary").
*   **SELinux as a Solution:**
    *   SELinux implements **Mandatory Access Control (MAC)** for the Linux kernel.
    *   **MAC Principles:**
        *   Access is governed by a system-wide security **policy**.
        *   This policy defines authorization rules for interactions between subjects (processes) and objects (files, sockets, etc.).
        *   The policy can only be changed by a system administrator (not regular users or applications).
        *   Users/applications *cannot* override or bypass the policy rules (e.g., cannot make a file world-readable if the policy forbids it).
*   **Integration into Android:**
    *   Introduced starting with **Android 4.3**.
    *   Based on the **SEAndroid** project, which adapted SELinux for Android-specific features (like Binder IPC).
    *   **Purpose in Android:**
        *   To confine core system daemons (services) and user applications into distinct **security domains** (also known as contexts or labels).
        *   To define specific **access policies** detailing what actions each domain is allowed to perform on which resources (other domains, files, etc.). Provides finer-grained control than DAC alone.
*   **Enforcement Status (as described in the text for Android 4.4):**
    *   **Global Mode:** SELinux was set to **enforcing mode** system-wide starting in Android 4.4. In enforcing mode, policy violations are actively *blocked* and typically result in errors.
    *   **Policy Scope (as of 4.4):** However, strict policy enforcement was initially applied primarily to **core system daemons**.
    *   **Application Domain Status (as of 4.4):** User applications ran in a **permissive domain**. This means SELinux policy violations *caused by applications* were logged (e.g., to `dmesg` or logcat) but were *not* blocked or cause runtime errors for the app.
    *   *(Note: Later Android versions significantly expanded the scope of SELinux enforcement to cover applications more strictly)*.

## System Updates

*   **Update Methods:**
    *   **Over-the-Air (OTA):** Updates downloaded directly to the device over a network connection.
    *   **PC Connection:** Pushing an update image from a computer using tools like:
        *   Standard **Android Debug Bridge (ADB)** client.
        *   Vendor-specific applications.
*   **Recovery OS ("Recovery"):**
    *   **Necessity:** Standard Android OS cannot directly modify critical low-level components like the baseband (modem) firmware or bootloader.
    *   **Function:** A special-purpose, minimal operating system used for applying system updates and performing other low-level tasks.
    *   **Access:** Has exclusive access to all device hardware during the update process.
*   **OTA Update Process:**
    1.  An **OTA package** (typically a ZIP file with an embedded digital signature) is downloaded to the device.
    2.  The package contains the update files and a **script** defining the update steps.
    3.  The device reboots into the **Recovery OS**.
    4.  Recovery verifies the signature of the OTA package.
    5.  If the signature is valid, Recovery interprets the script and applies the update.
*   **Manual Update Process:**
    1.  User manually boots the device into Recovery mode (using a device-specific key combination during startup).
    2.  User navigates the Recovery menu interface (usually via hardware buttons like Volume/Power).
    3.  User selects the update package (e.g., from internal storage or SD card) to apply manually.
*   **Signature Verification (Security):**
    *   **Requirement:** On production (consumer) devices, the Recovery OS is typically locked down to *only* accept update packages that are digitally signed by the **device manufacturer** (or the entity controlling the platform keys, like Google for Pixel devices).
    *   **Mechanism:** The update signature is usually embedded within the ZIP file format (e.g., in the comment section). Recovery extracts and cryptographically verifies this signature *before* proceeding with the installation.
    *   **Purpose:** Prevents unauthorized modification of the system software with potentially malicious code.
*   **Unlocking and Customization:**
    *   **Applicability:** Some devices (historically Nexus, dedicated developer devices, some vendor models) allow bypassing standard restrictions.
    *   **Bootloader Unlocking:** The process of switching the device's bootloader to a mode that allows flashing custom images.
        *   **NOT** the same as SIM unlocking (which allows using different carrier SIM cards).
        *   Typically **wipes all user data (factory reset)** as a security measure to prevent a new, potentially untrusted OS from accessing the previous user's data.
        *   Usually **voids the device warranty**.
    *   **Capabilities after Unlocking:**
        *   Allows replacing the stock Recovery OS with a custom one (e.g., TWRP).
        *   Allows disabling the system update signature verification check.
        *   Enables installation of third-party operating systems (custom ROMs) or modified stock updates.

## Verified Boot

*   **Purpose:** To ensure the integrity of the Android system partition (prevent undetected modification or corruption). Supported since Android 4.4.
*   **Core Technology:** Uses `dm-verity` (Device-Mapper verity target) from the Linux kernel.
*   **Mechanism: Cryptographic Hash Tree**
    *   Calculates cryptographic hashes for all underlying data blocks of the system partition (leaf nodes).
    *   Builds a tree by hashing the hashes at lower levels, culminating in a single **root hash**.
    *   Changing *any* data block changes its hash, propagating up and ultimately changing the root hash.
*   **Trust Anchor: Root Hash Verification**
    *   The single root hash represents the integrity of the entire partition.
    *   This root hash is typically signed or verified using a **trusted public key** (e.g., stored on the boot partition). This confirms the hash belongs to an authentic system image.
*   **Runtime Integrity Checking:**
    *   Checks occur transparently whenever a block is read from the verified partition *during normal operation*.
    *   The kernel reads the block, recalculates its hash, and compares it against the expected hash value stored within the verified hash tree (loaded at boot).
    *   **Mismatch:** Indicates tampering or corruption. The read operation fails with an **I/O error**, preventing the potentially malicious/corrupt data from being used.
*   **Prerequisite: Secure Boot Chain (Chain of Trust)**
    *   The kernel performs the `dm-verity` checks, so the kernel itself must be trusted.
    *   Kernel integrity is typically verified *before* it's loaded, as part of a secure boot process.
    *   This process usually starts from an **unchangeable hardware key** ("burned" into the device).
    *   This key verifies the initial bootloader(s), which in turn verify the kernel.
    *   Only a verified kernel can be trusted to correctly enforce `dm-verity`.

**Explanation of Verified Boot**

Imagine you want to be absolutely sure that the operating system files on your phone (the core Android system) haven't been secretly modified by malware or corrupted. Just checking them once at startup isn't enough, because something could try to change them while the phone is running. How can you continuously ensure their integrity without having to re-read and compare every single file constantly (which would be very slow)?

This is where Verified Boot, using a Linux feature called dm-verity, comes in.

1. **The Problem:** How to efficiently check if large amounts of data (like the Android system partition) have been tampered with.
    
2. **The Core Idea: Hash Tree (dm-verity)**
    
    - Instead of checking the files directly, dm-verity works at the level of raw storage blocks (the chunks of data on the disk).
        
    - It calculates a cryptographic hash (like a unique fingerprint) for each data block on the system partition. These are the "leaves" of the tree.
        
    - Then, it takes hashes of pairs (or small groups) of those leaf hashes to create a level above.
        
    - It keeps doing this – hashing the hashes – building layers upwards until there's only one single hash at the very top: the **root hash**.
        
    - **Crucially:** If any single data block at the bottom is changed, its hash will change, which will change the hash above it, and so on, all the way up to the root hash. Therefore, the root hash acts as a master fingerprint for the entire partition.
        
3. **Trusting the Root Hash:** How do we know the root hash itself is the correct one for an untampered system?
    
    - The legitimate root hash (calculated by the manufacturer or OS builder for the original, clean system) is digitally signed using a private key.
        
    - The corresponding **public key** is stored in a place the early boot process can trust (like the boot partition).
        
    - When the device boots, it can use this public key to verify the signature on the root hash, confirming that this root hash belongs to an authentic system image.
        
4. **Runtime Checking:**
    
    - Once the root hash is verified, the system loads the entire hash tree into memory.
        
    - Now, whenever the running Android system needs to read a block of data from the system partition:
        
        - The kernel reads the physical block.
            
        - It recalculates the hash for that block on the fly.
            
        - It compares this newly calculated hash with the expected hash stored in the hash tree (which was loaded at boot and validated via the root hash).
            
        - **Match:** The data is considered authentic, and the read operation succeeds.
            
        - **Mismatch:** This means the data block on disk has been altered since the hash tree was created! The kernel flags this as corruption and returns an I/O error instead of giving the bad data to the requesting process. This prevents modified system code from running.
            
5. **The Chain of Trust:** This whole process relies on the idea that the software doing the checking (the Linux kernel running dm-verity) is itself trustworthy. How is that ensured?
    
    - This requires a **secure boot process** that starts even before the kernel loads.
        
    - It typically begins with a **hardware root of trust**: a key embedded immutably ("burned") into the device's hardware (like the processor).
        
    - This hardware key verifies the signature of the first piece of bootloader software.
        
    - That bootloader then verifies the signature of the next stage bootloader (if any), and eventually verifies the signature of the **Linux kernel** before loading it.
        
    - Only if the kernel's signature is valid (meaning the kernel itself hasn't been tampered with) can it be trusted to correctly load the dm-verity hash tree and perform the runtime checks described above.
        

**In short:** Verified Boot uses a hash tree (dm-verity) to efficiently check the integrity of the system partition at runtime. This process is anchored by a root hash verified by a public key during boot. The trustworthiness of this entire check relies on a secure boot chain starting from a hardware key that verifies the bootloader and the kernel itself.
