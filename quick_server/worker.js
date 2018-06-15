/**
 * !!! This file can be found as worker.js in the quick_server folder !!!
 *
 * Provides worker oriented networking interface.
 *
 * Created by krause on 2016-06-22.
 */

export let PRE_DELAY = 500;
export let TIME_START = 500;
// has to be below 2min so the server doesn't remove the result
export let TIME_CAP = 1000*60;
export let TIME_MIN_INC = 10;
export let TIME_MUL_INC = 1.01;
export let ANIMATION = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"];
// ANIMATION = ["/", "-", "\\", "|"];
export let ANIMATION_TIME = 300;
export const VERSION = "0.5.0";

export class Worker {
  constructor() {
    const that = this;
    window.addEventListener("beforeunload", () => {
      Object.keys(tokens).forEach((ref) => {
        // we probably won't read the results but
        // the server still cancels properly
        that.cancel(ref);
      });
    });
    this._status = (req) => {};
    this._active = true;
    this._infoTitle = true;
    this._beforeTitle = null;
    this._ownTitle = null;
    this._req = 0;
    this._animationIx = 0;
    this._animationInFlight = false;
    this._starts = {};
    this._tokens = {};
    this._urls = {};
  }

  set status(status) {
    this._status = status;
  }

  get status() {
    return this._status;
  }

  set active(active) {
    this._active = active;
  }

  get active() {
    return this._active;
  }

  set infoTitle(infoTitle) {
    if(!infoTitle) {
      this.setAddTitle("");
    }
    this._infoTitle = infoTitle;
  }

  get infoTitle() {
    return this._infoTitle;
  }

  setAddTitle(addTitle) {
    if(!this._infoTitle) return;
    const curTitle = document.title;
    if(this._ownTitle && curTitle !== this._ownTitle) { // external change
      this._beforeTitle = curTitle;
    }
    if(!this._beforeTitle) {
      this._beforeTitle = curTitle;
    }
    this._ownTitle = this._beforeTitle + addTitle;
    document.title = this._ownTitle;
  } // setAddTitle

  sendRequest(url, obj, cb) {
    fetch(url, {
      "method": "POST",
      "headers": new Headers({
        "Content-Type": "application/json",
        "Content-Length": "" + obj.length,
      }),
      "body": obj,
    }).then((data) => {
      if(data.status !== 200 || !data.ok) {
        console.warn("response not okay", data);
        throw new Error("response not okay");
      }
      const ct = data.headers.get("content-type");
      if(ct && ct.includes("application/json")) {
        return data.json();
      }
      throw new TypeError("response not JSON encoded");
    }).then((data) => cb(null, data)).catch((e) => cb(e, null));
  }

  changeStatus(inc, error) {
    if(this._req < 0) return;
    if(error) {
      this._req = -1;
    } else if(inc) {
      this._req += 1;
    } else {
      this._req -= 1;
    }
    this.titleStatus();
    this._status(this._req);
  } // changeStatus

  titleStatus() {
    if(this._req <= 0) {
      this.setAddTitle("");
      return;
    }
    let txt = " " + ANIMATION[this._animationIx % ANIMATION.length];
    if(this._req > 1) {
      txt += " (" + this._req + "x)";
    }
    this.setAddTitle(txt);
    if(this._infoTitle && !this._animationInFlight) {
      this._animationIx = (this._animationIx + 1) % ANIMATION.length;
      this._animationInFlight = true;
      const that = this;
      setTimeout(() => {
        that._animationInFlight = false;
        that.titleStatus();
      }, ANIMATION_TIME);
    }
  } // titleStatus

  get_payload(data, url, cb) {
    if(!data["continue"]) {
      cb(JSON.parse(data["result"]));
      return;
    }
    const that = this;
    const keys = data["result"];
    const res = {};
    keys.forEach((k) => {
      const obj = JSON.stringify({
        "action": "cargo",
        "token": k,
      });
      that.sendRequest(url, obj, (err, data) => {
        if(err) {
          console.warn("Failed to retrieve cargo " + k);
          that.changeStatus(false, true);
          return console.warn(err);
        }
        if(k !== data["token"]) {
          console.warn("Mismatching token " + k + " !== " + data["token"]);
          that.changeStatus(false, true);
          return;
        }
        res[k] = data["result"];
        check_finished();
      });
    });

    const check_finished = () => {
      if(!keys.every((k) => k in res)) {
        return;
      }
      const d = keys.map((k) => res[k]).join(''); // string may be too long :(
      keys.forEach((k) => { // free memory
        res[k] = null;
      });
      cb(JSON.parse(d));
    } // check_finished
  } // get_payload

  postTask(ref) {
    const that = this;
    setTimeout(() => {
      if(!that._starts[ref]) return;
      const s = that._starts[ref];
      const url = s["url"];
      const cb = s["cb"];
      that._starts[ref] = null;
      that.changeStatus(true, false);
      const obj = JSON.stringify({
        "action": "start",
        "payload": s["payload"],
      });
      that.sendRequest(url, obj, (err, data) => {
        if(err) {
          console.warn("Failed to start " + ref);
          that.changeStatus(false, true);
          return console.warn(err);
        }
        that._cancel(ref, (err) => {
          if(err) {
            console.warn("Failed to cancel " + ref);
            that.changeStatus(false, true);
            return console.warn(err);
          }
        });
        if(data["done"]) {
          that.get_payload(data, url, (d) => {
            that.execute(cb, d);
          });
        } else {
          const token = +data["token"];
          that._urls[ref] = url;
          that._tokens[ref] = token;
          that.monitor(ref, token, cb, TIME_START);
        }
      });
    }, PRE_DELAY);
  } // postTask

  monitor(ref, token, cb, delay) {
    if(this._tokens[ref] !== token) {
      this.changeStatus(false, false);
      return;
    }
    const url = this._urls[ref];
    const obj = JSON.stringify({
      "action": "get",
      "token": token,
    });
    const that = this;
    this.sendRequest(url, obj, (err, data) => {
      if(err) {
        console.warn("Error while retrieving " + ref + " token: " + token);
        that.changeStatus(false, true);
        return console.warn(err);
      }
      const cur_token = +data["token"];
      if(cur_token !== that._tokens[ref]) {
        // late response
        that.changeStatus(false, false);
        return;
      }
      if(cur_token !== token) {
        // wrong response
        console.warn("Error while retrieving " + ref);
        that.changeStatus(false, true);
        return console.warn({
          "err": "token mismatch: " + cur_token + " instead of " + token,
        });
      }
      if(data["done"]) {
        that._tokens[ref] = -1;
        that._urls[ref] = null;
        that.get_payload(data, url, (d) => {
          that.execute(cb, d);
        });
      } else if(data["continue"]) {
        setTimeout(() => {
          const newDelay = Math.min(Math.max(
            delay * TIME_MUL_INC, delay + TIME_MIN_INC), TIME_CAP);
          that.monitor(ref, token, cb, newDelay);
        }, delay);
      } else {
        that.changeStatus(false, false);
      }
    });
  } // monitor

  _cancel(ref, cb) {
    if(!(ref in this._tokens && this._tokens[ref] >= 0)) return;
    const token = this._tokens[ref];
    const url = this._urls[ref];
    const obj = JSON.stringify({
      "action": "stop",
      "token": token,
    });
    this._tokens[ref] = -1;
    this._urls[ref] = null;
    this.sendRequest(url, obj, (err, data) => {
      if(err) {
        return cb(err);
      }
      return cb(+data["token"] !== token && {
        "err": "token mismatch: " + data["token"] + " instead of " + token,
      });
    });
  } // _cancel

  execute(cb, data) {
    let err = true;
    try {
      cb(data);
      err = false;
    } finally {
      if(err) {
        this.changeStatus(false, true);
      } else {
        this.changeStatus(false, false);
      }
    }
  } // execute

  post(ref, url, payload, cb) {
    if(!this._active) return;
    this._starts[ref] = {
      "url": url,
      "cb": cb,
      "payload": payload,
    };
    this.postTask(ref);
  }

  cancel(ref) {
    const that = this;
    this._cancel(ref, (err) => {
      that.changeStatus(false, !!err);
      if(err) {
        console.warn("Failed to cancel " + ref);
        return console.warn(err);
      }
    });
  }
} // Worker

export class VariableHandler {
  constructor(worker, objectPath) {
    this._worker = worker;
    this._objectPath = objectPath;
    this._curQuery = {};
  }


} // VariableHandler

class Variable {
  constructor(hnd) {
    this._hnd = hnd;
    this._sync = false;
    this._value = null;
  }

  has() {
    return this._sync;
  }

  get value() {
    if(!this.has()) {
      throw new Error("variable not in sync");
    }
    return this._value;
  }

} // Variable

class Value extends Variable {

} // Value

class LazyValue extends Variable {

} // LazyValue

class LazyMap extends Variable {

} // LazyMap
