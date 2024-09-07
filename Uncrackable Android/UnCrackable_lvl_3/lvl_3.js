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

    var xorkey  = "pizzapizzapizzapizzapizz"

    var MainActivity = Java.use("sg.vantagepoint.uncrackable3.MainActivity");
    MainActivity.$init.implementation = function() {   //Default constructor implementation
        this.$init();
        SecretGenerator();
    };

    function xorByteArrays(a1, a2) { // To get the actual secret string
      var i;
      const ret = new Uint8Array(new ArrayBuffer(24));
      for (i = 0; i < 24; i++) {
        ret[i] = a1[i] ^ a2.charCodeAt(i);
      }
      return ret;
    }


    function SecretGenerator() {
      Interceptor.attach(Module.findBaseAddress('libfoo.so').add(0xfa0), {
        onEnter: function(args) {
          this.answerLocation = args[0];
        },
        onLeave: function(retval) {
          var encodedAnswer = new Uint8Array(this.answerLocation.readByteArray(24));
          console.log(encodedAnswer);
          var decodedAnswer = xorByteArrays(encodedAnswer, xorkey);
          console.log("Secret key: " + String.fromCharCode.apply(null, decodedAnswer));
        }
      });
    }

})