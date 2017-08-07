/**
 * !!! This file can be found as worker.js in the quick_server folder !!!
 *
 * Provides worker oriented networking interface.
 *
 * Created by krause on 2016-06-22.
 */
"use strict";

window.quick_server = window.quick_server || {}; // init namespace

window.quick_server.Worker = function() {
  var that = this;
  var timeStart = 500;
  var timeCap = 1000*60; /* has to be below 2min so the server doesn't remove the result */
  var timeMinInc = 10;
  var timeMulInc = 1.01;

  this.version = "0.3.0";

  var status = (req) => {};
  this.status = function(_) {
    if(!arguments.length) return status;
    status = _;
  };

  var active = true;
  this.active = function(_) {
    if(!arguments.length) return active;
    active = _;
  };

  var infoTitle = true;
  this.infoTitle = function(_) {
    if(!arguments.length) return infoTitle;
    if(!_) {
      setAddTitle("");
    }
    infoTitle = _;
  };

  var beforeTitle = null;
  var ownTitle = null;
  function setAddTitle(addTitle) {
    if(!infoTitle) return;
    var curTitle = document.title;
    if(ownTitle && curTitle !== ownTitle) { // external change
      beforeTitle = curTitle;
    }
    if(!beforeTitle) {
      beforeTitle = curTitle;
    }
    ownTitle = beforeTitle + addTitle;
    document.title = ownTitle;
  } // setAddTitle

  var sendRequest = function(url, obj, cb) {
    if(typeof d3 !== 'undefined') { // d3 compatibility
      d3.json(url).header("Content-Type", "application/json").post(obj, (err, data) => {
        cb(err, data);
      });
      return;
    }
    if(typeof fetch === "function") {
      fetch(url, {
        "method": "POST",
        "headers": new Headers({
          "Content-Type": "application/json",
          "Content-Length": "" + obj.length,
        }),
        "body": obj,
      }).then((data) => {
        if(data.status !== 200 || !data.ok) {
          throw { msg: "response not okay", data };
        }
        var ct = data.headers.get("content-type");
        if(ct && ct.includes("application/json")) {
          return data.json();
        }
        throw new TypeError("response not JSON encoded");
      }).then((data) => cb(null, data)).catch((e) => cb(e, null));
      return;
    }
    throw { "err": "unimplemented", };
  };
  this.sendRequest = function(_) {
    if(!arguments.length) return sendRequest;
    sendRequest = _;
  };

  var preDelay = 500;
  this.preDelay = function(_) {
    if(!arguments.length) return preDelay;
    preDelay = _;
  };

  var req = 0;
  function changeStatus(inc, error) {
    if(req < 0) return;
    if(error) {
      req = -1;
    } else if(inc) {
      req += 1;
    } else {
      req -= 1;
    }
    titleStatus();
    status(req);
  } // changeStatus

  var animationIx = 0;
  // var animation = [ "/", "-", "\\", "|", ];
  var animation = [ "⠋", "⠙", "⠸", "⠴", "⠦", "⠇", ];
  var animationTime = 300;
  var animationInFlight = false;
  function titleStatus() {
    if(req <= 0) {
      setAddTitle("");
      return;
    }
    var txt = " " + animation[animationIx];
    if(req > 1) {
      txt += " (" + req + "x)";
    }
    setAddTitle(txt);
    if(infoTitle && !animationInFlight) {
      animationIx = (animationIx + 1) % animation.length;
      animationInFlight = true;
      setTimeout(() => {
        animationInFlight = false;
        titleStatus();
      }, animationTime);
    }
  } // titleStatus

  function get_payload(data, url, cb) {
    if(!data["continue"]) {
      cb(JSON.parse(data["result"]));
      return;
    }
    var keys = data["result"];
    var res = {};
    keys.forEach((k) => {
      var obj = JSON.stringify({
        "action": "cargo",
        "token": k,
      });
      sendRequest(url, obj, (err, data) => {
        if(err) {
          console.warn("Failed to retrieve cargo " + k);
          changeStatus(false, true);
          return console.warn(err);
        }
        if(k !== data["token"]) {
          console.warn("Mismatching token " + k + " !== " + data["token"]);
          changeStatus(false, true);
          return;
        }
        res[k] = data["result"];
        check_finished();
      });
    });

    function check_finished() {
      if(!keys.every((k) => k in res)) {
        return;
      }
      var d = keys.map((k) => res[k]).join(''); // string may be too long :(
      keys.forEach((k) => { // free memory
        res[k] = null;
      });
      cb(JSON.parse(d));
    } // check_finished

  } // get_payload

  var starts = {};
  var tokens = {};
  var urls = {};
  function postTask(ref) {
    setTimeout(() => {
      if(!starts[ref]) return;
      var s = starts[ref];
      var url = s["url"];
      var cb = s["cb"];
      starts[ref] = null;
      changeStatus(true, false);
      var obj = JSON.stringify({
        "action": "start",
        "payload": s["payload"],
      });
      sendRequest(url, obj, (err, data) => {
        if(err) {
          console.warn("Failed to start " + ref);
          changeStatus(false, true);
          return console.warn(err);
        }
        cancel(ref, (err) => {
          if(err) {
            console.warn("Failed to cancel " + ref);
            changeStatus(false, true);
            return console.warn(err);
          }
        });
        if(data["done"]) {
          get_payload(data, url, (d) => {
            execute(cb, d);
          });
        } else {
          var token = +data["token"];
          urls[ref] = url;
          tokens[ref] = token;
          monitor(ref, token, cb, timeStart);
        }
      });
    }, preDelay);
  } // postTask

  function monitor(ref, token, cb, delay) {
    if(tokens[ref] !== token) {
      changeStatus(false, false);
      return;
    }
    var url = urls[ref];
    var obj = JSON.stringify({
      "action": "get",
      "token": token,
    });
    sendRequest(url, obj, (err, data) => {
      if(err) {
        console.warn("Error while retrieving " + ref + " token: " + token);
        changeStatus(false, true);
        return console.warn(err);
      }
      var cur_token = +data["token"];
      if(cur_token !== tokens[ref]) {
        // late response
        changeStatus(false, false);
        return;
      }
      if(cur_token !== token) {
        // wrong response
        console.warn("Error while retrieving " + ref);
        changeStatus(false, true);
        return console.warn({ "err": "token mismatch: " + cur_token + " instead of " + token, });
      }
      if(data["done"]) {
        tokens[ref] = -1;
        urls[ref] = null;
        get_payload(data, url, (d) => {
          execute(cb, d);
        });
      } else if(data["continue"]) {
        setTimeout(() => {
          var newDelay = Math.min(Math.max(delay * timeMulInc, delay + timeMinInc), timeCap);
          monitor(ref, token, cb, newDelay);
        }, delay);
      } else {
        changeStatus(false, false);
      }
    });
  } // monitor

  function cancel(ref, cb) {
    if(!(ref in tokens && tokens[ref] >= 0)) return;
    var token = tokens[ref];
    var url = urls[ref];
    var obj = JSON.stringify({
      "action": "stop",
      "token": token,
    });
    tokens[ref] = -1;
    urls[ref] = null;
    sendRequest(url, obj, (err, data) => {
      if(err) {
        return cb(err);
      }
      return cb(+data["token"] !== token && { "err": "token mismatch: " + data["token"] + " instead of " + token, });
    });
  } // cancel

  function execute(cb, data) {
    var err = true;
    try {
      cb(data);
      err = false;
    } finally {
      if(err) {
        changeStatus(false, true);
      } else {
        changeStatus(false, false);
      }
    }
  } // execute

  this.post = function(ref, url, payload, cb) {
    if(!active) return;
    starts[ref] = {
      "url": url,
      "cb": cb,
      "payload": payload,
    };
    postTask(ref);
  };
  this.cancel = function(ref) {
    cancel(ref, (err) => {
      changeStatus(false, !!err);
      if(err) {
        console.warn("Failed to cancel " + ref);
        return console.warn(err);
      }
    });
  };

  window.addEventListener("beforeunload", () => {
    Object.keys(tokens).forEach((ref) => {
      // we probably won't read the results but the server still cancels properly
      that.cancel(ref);
    });
  });
} // quick_server.Worker
