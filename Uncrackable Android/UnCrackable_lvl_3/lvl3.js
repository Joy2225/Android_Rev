Java.perform(function(){
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
        onEnter: function(args) {
          this.fridaDetected = 0;
          if (args[0].readUtf8String().indexOf("frida") != -1) {
            this.fridaDetected = 1;
          }
          else {
            this.fridaDetected = 0;
          }
    
        },
        onLeave: function(retval) {
          if (this.fridaDetected == 1) {
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


    /*
    Interceptor.attach(Module.findBaseAddress('libfoo.so').add(0xfa0), {
    onEnter: function(args) {
      console.log("Secret generator on enter, address of secret: " + args[0]);
      this.answerLocation = args[0];
      console.log(hexdump(this.answerLocation, {
        offset: 0,
        length: 0x20,
        header: true,
        ansi: true
      }));
    },
    onLeave: function(retval) {
      console.log("Secret generator on leave");
      console.log(hexdump(this.answerLocation, {
        offset: 0,
        length: 0x20,
        header: true,
        ansi: true
      }));
    }
  });

    */

  var MainActivity = Java.use("sg.vantagepoint.uncrackable3.MainActivity");
  MainActivity.$init.implementation = function() {   //Default constructor implementation
      this.$init();
      SecretGenerator();
  };

  const secretLength = 24;
  var xorkey = undefined;
  Interceptor.attach(Module.findExportByName("libc.so", "strncpy"), {
    onEnter: function(args) {
      if (args[1].readCString().indexOf("pizza")!=-1) {
        xorkey = new Uint8Array(args[1].readByteArray(secretLength));
        console.log(xorkey);
      }
    },
  });

  function xorByteArrays(a1, a2) {
    var i;
    const ret = new Uint8Array(new ArrayBuffer(a2.byteLength));
    for (i = 0; i < a2.byteLength; i++) {
      ret[i] = a1[i] ^ a2[i];
    }
    return ret;
  }


  function SecretGenerator() {
    Interceptor.attach(Module.findBaseAddress('libfoo.so').add(0x12c0), {
      onEnter: function(args) {
        this.answerLocation = args[0];
      },
      onLeave: function(retval) {
        var encodedAnswer = new Uint8Array(this.answerLocation.readByteArray(secretLength));
        console.log(encodedAnswer);
        var decodedAnswer = xorByteArrays(encodedAnswer, xorkey);
        console.log(xorkey)
        console.log("Secret key: " + String.fromCharCode.apply(null, decodedAnswer));
      }
    });
  }
    
});