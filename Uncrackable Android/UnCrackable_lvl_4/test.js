Java.perform(function(){
    let root = Java.use("♫.ᵤ");
    root["₤"].implementation = function () {
        console.log("Client side root checker called");
        return false;
    };

    root["θ"].overload().implementation = function () {
        console.log("rootbear root checker called");
        return false;
    }
    // console.log(Module.getBaseAddress("libnative-lib.so"))

    
});
const SYSCALL_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    60: "exit",
    39: "getpid",
    231: "exit_group",
    257: "openat",
    5: "fstat",
    9: "mmap",
    10: "mprotect",
    12: "brk",
    62: "kill",
    202: "futex",
    218: "set_tid_address",
    231: "exit_group",
    158: "arch_prctl",
    57: "fork",
    59: "execve",
    63: "uname",
    80: "creat",
    97: "getuid",
    102: "getgid",
    104: "setuid",
    105: "setgid"
    // Add more if needed
};

var isLibraryLoaded = false;
var targetlib = "libnative-lib.so";
Interceptor.attach(Module.getExportByName(null, "openat"), {
    onEnter(args) {
        var libraryPath = Memory.readCString(args[1]);
        console.log("openat called with path:", libraryPath);
        // if(libraryPath.includes(targetlib)) {
        //     console.log("Library loaded:", libraryPath);
        //     isLibraryLoaded = true;
        // }
    },
    // onLeave(retval) {
    //     if (isLibraryLoaded) {
    //         const targetModule = Process.findModuleByName(targetlib);
    //         console.log("Target module is loaded as " + targetModule.base);
    //     }
    // }
});


// function stalker(threadId) {
    Stalker.follow(Process.getCurrentThreadId(), {
        events: {

            ret: true,
            call: false,
            exec: false,

        },
        // onReceive: (events) => {
        //     for (let i = 0; i < events.length; i++) {
        //         const event = events[i];
                
        //     }
        // },
        transform: function(iterator){
            var instruction = null;
            while((instruction=iterator.next()) != null){

            // if(instruction.mnemonic.indexOf("syscall") !== -1) 
                iterator.putCallout(function(context){
                    var instruction = Instruction.parse(context.pc) 
                    if(instruction.mnemonic.indexOf("syscall") === -1) return;
                    console.log(instruction.mnemonic)
                    // var rax = context.rax;
                    // var syscallNum = rax.toInt32(); // syscall number is in rax register
                    // console.log(rax);
                    console.log(instruction.address)
                    console.log("Call instruction: " + instruction);
                })
                

                iterator.keep();
            }
        }
    });
// }
