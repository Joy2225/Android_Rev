Java.perform(function() {

    let Runtime = Java.use("java.lang.Runtime");

    // Hook exec(String)
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        console.log("[+] Intercepted Runtime.exec(): " + cmd);
        return this.exec(cmd); // Call original method
    };



});

