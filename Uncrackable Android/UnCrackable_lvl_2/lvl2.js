Java.perform(function(){
    let c = Java.use("sg.vantagepoint.a.b");
    c["a"].implementation = function () {
        return false
    };

    c["b"].implementation = function () {
        return false;
    };

    c["c"].implementation = function () {
        return false;
    };
});

/*
var strncmp_adr=Module.getBaseAddress("libfoo.so").add(0x00000ffb);
Interceptor.attach(strncmp_adr, {
    onEnter: function (args) {
            console.log("Hookin the strncmp function");
            console.log("The secret string is: "+args[0].readCString());
    },
    onLeave: function (retval) {
    }
});
*/