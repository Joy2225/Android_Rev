Java.perform(function() {
    var File = Java.use("java.io.File");

    // Hook the constructor that takes (String parent, String child)
    File.$init.overload('java.lang.String', 'java.lang.String').implementation = function(parent, child) {
        console.log("[*] File constructor called:");
        console.log("    Parent Path: " + parent);
        console.log("    Child Name (str): " + child);

        // Call the original constructor
        return this.$init(parent, child);
    };

    var Uri = Java.use("android.net.Uri");
    Uri.getQueryParameter.overload('java.lang.String').implementation = function(key) {
        var value = this.getQueryParameter(key);
        console.log("[*] getQueryParameter called:");
        console.log("    Key: " + key);
        console.log("    Value: " + value);
        return value;  // Return the original value to keep the app behavior unchanged
    }
});
