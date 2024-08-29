Java.perform(function(){
    Interceptor.attach(Module.findExportByName("libc.so","strstr"), {
      onEnter: function(args){
        this.detectfrida = 0;
        if(args[0].readUtf8String().indexOf("frida") != -1){
          this.detectfrida = 1;
        }
        else{
          this.detectfrida = 0;
        }
      },
      onLeave: function(retval){
        if(this.detectfrida == 1){
          retval.replace(0);
        }
      }
    });

    let c = Java.use("sg.vantagepoint.util.RootDetection");
    c["checkRoot1"].implementation = function () {
        return false
    };

    c["checkRoot2"].implementation = function () {
        return false;
    };

    c["checkRoot3"].implementation = function () {
        return false;
    };

})