Java.perform(function() {

    let CSPBypassActivity = Java.use("b3nac.injuredandroid.CSPBypassActivity");
    CSPBypassActivity["$init"].implementation = function () {
        console.log(`CSPBypassActivity.$init is called`);
        this["$init"]();
    };

    let m = Java.use("b3nac.injuredandroid.CSPBypassActivity");
m["M"].implementation = function () {
    console.log(`CSPBypassActivity.M is called`);
    this["M"]();
};

let l = Java.use("b3nac.injuredandroid.CSPBypassActivity");
l["L"].implementation = function () {
    console.log(`CSPBypassActivity.L is called`);
    this["L"]();
};

let create = Java.use("b3nac.injuredandroid.CSPBypassActivity");
create["onCreate"].implementation = function (bundle)  {
    console.log(`CSPBypassActivity.onCreate is called`);
    this["onCreate"](bundle);
};

}

);