// Java.perform(() => {
//     function dumpByteBufferSafe(bb) {
//         try {
//             const limit = bb.limit();
//             const pos = bb.position();
//             let hexDump = '';

//             for (let i = pos; i < limit; i++) {
//                 const byte = bb.get(i);
//                 hexDump += ('0' + (byte & 0xff).toString(16)).slice(-2) + ' ';
//             }

//             return hexDump.trim();
//         } catch (err) {
//             return '[Error dumping ByteBuffer: ' + err + ']';
//         }
//     }

//     let b = Java.use("c.a.c.a.i$b");
//     b["a"].implementation = function (byteBuffer) {
//         console.log(`b.a is called: byteBuffer=${byteBuffer}`);
//         console.log(`[b.a] ByteBuffer Dump: ${dumpByteBufferSafe(byteBuffer)}`);
//         return this["a"](byteBuffer);
//     };

//     let a = Java.use("c.a.c.a.i$a");
//     a["a"].implementation = function (byteBuffer, interfaceC0071b) {
//         console.log(`a.a is called: byteBuffer=${byteBuffer}, interfaceC0071b=${interfaceC0071b}`);
//         console.log(`[a.a] ByteBuffer Dump: ${dumpByteBufferSafe(byteBuffer)}`);
//         return this["a"](byteBuffer, interfaceC0071b);
//     };

//     let d = Java.use("b.d.a.a.a");
//     d["a"].implementation = function (str, list, map, i, str2) {
//     console.log(`a.a is called: str=${str}, list=${list}, map=${map}, i=${i}, str2=${str2}`);
//     console.log(list.get(0));
//     let result = this["a"](str, list, map, i, str2);
//     return result;
// };
// });


Java.perform(() => {
    let cls = Java.use("b.d.a.a.a");
    cls.a.overload(
      'java.lang.String',
      'java.util.List',
      'java.util.Map',
      'int',
      'java.lang.String'
    ).implementation = function (url, list, map, timeout, type) {
      console.log("[Bypass] Called with URL:", url);
      return true;
    };
  });
  