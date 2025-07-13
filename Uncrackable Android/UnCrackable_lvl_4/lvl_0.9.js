Java.perform(function(){
    // console.log(Module.findExportByName("libtool-checker.so", "Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot"));
    // Interceptor.attach(Module.findExportByName("libtool-checker.so", "Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot"), {
    //     onEnter: function(args) {
    //         console.log("Enter rootchecker");
    //     },
    //     onLeave: function(retval) {
    //       retval.replace(0);
    //     }
    //   });


    let root = Java.use("♫.ᵤ");
    root["₤"].implementation = function () {
        console.log("Client side root checker called");
        return false;
    };

    root["θ"].overload().implementation = function () {
        console.log("rootbear root checker called");
        return false;
    }
    console.log(Module.getBaseAddress("libnative-lib.so"))

    
});

Process.enumerateThreads().forEach(function(thread) {
    console.log("Thread ID: " + thread.id + ", Name: " + thread.name);
    Stalker.follow(thread.id, {
        events: {
            call: true,
            ret: true,
            exec: true
        },
        onReceive: function(events) {
            console.log("Received events: ", events);
        },
        onCallSummary: function(summary) {
            console.log("Call summary: ", summary);
        }
    });
    });
