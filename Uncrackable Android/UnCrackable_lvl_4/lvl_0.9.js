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



    let c = Java.use("b.a.a.b");

    c["j"].implementation = function () {
        console.log("disable root");
        return false;
    };

    c["e"].implementation = function () {
        return false;
    };

    // c["ö"].implementation = function () {
    //     return false;
    // };


    
});