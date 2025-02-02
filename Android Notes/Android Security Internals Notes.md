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