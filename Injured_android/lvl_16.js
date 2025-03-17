Java.perform(function() {
    let g = Java.use("d.s.d.g");
    g["a"].implementation = function (obj, obj2) {
        console.log(`g.a is called: obj=${obj}, obj2=${obj2}`);
        let result = this["a"](obj, obj2);
        console.log(`g.a result=${result}`);
        return result;
    };
});