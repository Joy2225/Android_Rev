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