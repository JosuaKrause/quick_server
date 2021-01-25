/**
 * !!! This file can be found as worker.legacy.js in the quick_server folder !!!
 *
 * Provides worker oriented networking interface.
 * This version does not need a transpiler and can be loaded directly in HTML.
 *
 * Created by krause on 2019-03-06.
 */

window.CONFIG = {
  preDelay: 500,
  timeStart: 500,
  // has to be below 2min so the server doesn't remove the result
  timeCap: 1000*60,
  timeMinInc: 10,
  timeMulInc: 1.01,
  animation: ['⠋', '⠙', '⠸', '⠴', '⠦', '⠇'],
  // animation: ['/', '-', '\\', '|'],
  animationTime: 300,
};
window.VERSION = '0.7.12';

class Worker {
  constructor() {
    window.addEventListener('beforeunload', () => {
      Object.keys(this._tokens).forEach((ref) => {
        // we probably won't read the results but
        // the server still should cancel properly
        this.cancel(ref);
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
    if (!infoTitle) {
      this.setAddTitle('');
    }
    this._infoTitle = infoTitle;
  }

  get infoTitle() {
    return this._infoTitle;
  }

  setAddTitle(addTitle) {
    if (!this._infoTitle) return;
    const curTitle = document.title;
    if (this._ownTitle && curTitle !== this._ownTitle) { // external change
      this._beforeTitle = curTitle;
    }
    if (!this._beforeTitle) {
      this._beforeTitle = curTitle;
    }
    this._ownTitle = this._beforeTitle + addTitle;
    document.title = this._ownTitle;
  } // setAddTitle

  sendRequest(url, obj, cb) {
    const BENIGN_ERR = 'BENIGN_ERR';
    fetch(url, {
      method: 'POST',
      headers: new Headers({
        'Content-Type': 'application/json',
        'Content-Length': `${obj.length}`,
      }),
      body: obj,
    }).then((data) => {
      if (data.status !== 200 || !data.ok) {
        cb({
          err: data.statusText,
          code: data.status,
        }, null);
        throw new Error(BENIGN_ERR);
      }
      const ct = data.headers.get('content-type');
      if (ct && ct.includes('application/json')) {
        return data.json();
      }
      throw new TypeError('response not JSON encoded');
    }).then((data) => cb(null, data)).catch((e) => {
      if (e.message !== BENIGN_ERR) cb(e, null);
    });
  }

  changeStatus(inc, error) {
    if (this._req < 0) return;
    if (error) {
      this._req = -1;
    } else if (inc) {
      this._req += 1;
    } else {
      this._req -= 1;
    }
    this.titleStatus();
    this._status(this._req);
  } // changeStatus

  titleStatus() {
    if (this._req <= 0) {
      this.setAddTitle('');
      return;
    }
    const anim = CONFIG.animation;
    let txt = ` ${anim[this._animationIx % anim.length]}`;
    if (this._req > 1) {
      txt += ` (${this._req}x)`;
    }
    this.setAddTitle(txt);
    if (this._infoTitle && !this._animationInFlight) {
      this._animationIx = (this._animationIx + 1) % anim.length;
      this._animationInFlight = true;
      setTimeout(() => {
        this._animationInFlight = false;
        this.titleStatus();
      }, CONFIG.animationTime);
    }
  } // titleStatus

  getPayload(data, url, cb, errCb) {
    if (!data.continue) {
      cb(JSON.parse(data.result));
      return;
    }
    const keys = data.result;
    const res = {};
    keys.forEach((k) => {
      const obj = JSON.stringify({
        action: 'cargo',
        token: k,
      });
      this.sendRequest(url, obj, (err, data) => {
        if (err) {
          console.warn(`Failed to retrieve cargo ${k}`);
          this.changeStatus(false, true);
          console.warn(err);
          errCb && errCb(err);
          return;
        }
        if (k !== data.token) {
          const errMsg = `Mismatching token ${k} !== ${data.token}`;
          console.warn(errMsg);
          this.changeStatus(false, true);
          errCb && errCb({
            err: errMsg,
          });
          return;
        }
        res[k] = data.result;
        checkFinished();
      });
    });

    const checkFinished = () => {
      if (!keys.every((k) => k in res)) {
        return;
      }
      const d = keys.map((k) => res[k]).join(''); // string may be too long :(
      keys.forEach((k) => { // free memory
        res[k] = null;
      });
      cb(JSON.parse(d));
    }; // checkFinished
  } // getPayload

  postTask(ref) {
    setTimeout(() => {
      if (!this._starts[ref]) return;
      const s = this._starts[ref];
      const url = s.url;
      const cb = s.cb;
      const errCb = s.errCb;
      this._starts[ref] = null;
      this.changeStatus(true, false);
      const obj = JSON.stringify({
        action: 'start',
        payload: s.payload,
      });
      this.sendRequest(url, obj, (err, data) => {
        if (err) {
          console.warn(`Failed to start ${ref}`);
          this.changeStatus(false, true);
          console.warn(err);
          errCb && errCb(err);
          return;
        }
        this._cancel(ref, (err) => {
          if (err) {
            console.warn(`Failed to cancel ${ref}`);
            this.changeStatus(false, true);
            return console.warn(err);
          }
        });
        if (data.done) {
          this.getPayload(data, url, (d) => {
            this.execute(cb, d);
          }, errCb);
        } else {
          const token = +data.token;
          this._urls[ref] = url;
          this._tokens[ref] = token;
          this.monitor(ref, token, cb, errCb, CONFIG.timeStart);
        }
      });
    }, CONFIG.preDelay);
  } // postTask

  monitor(ref, token, cb, errCb, delay) {
    if (this._tokens[ref] !== token) {
      this.changeStatus(false, false);
      return;
    }
    const url = this._urls[ref];
    const obj = JSON.stringify({
      action: 'get',
      token: token,
    });
    this.sendRequest(url, obj, (err, data) => {
      if (err) {
        console.warn(`Error while retrieving ${ref} token: ${token}`);
        this.changeStatus(false, true);
        console.warn(err);
        errCb && errCb(err);
        return;
      }
      const curToken = +data.token;
      if (curToken !== this._tokens[ref]) {
        // late response
        this.changeStatus(false, false);
        return;
      }
      if (curToken !== token) {
        // wrong response
        console.warn(`Error while retrieving ${ref}`);
        this.changeStatus(false, true);
        const errData = {
          err: `token mismatch: ${curToken} instead of ${token}`,
        };
        console.warn(errData);
        errCb && errCb(errData);
        return;
      }
      if (data.done) {
        this._tokens[ref] = -1;
        this._urls[ref] = null;
        this.getPayload(data, url, (d) => {
          this.execute(cb, d);
        });
      } else if (data.continue) {
        setTimeout(() => {
          const newDelay = Math.min(
            Math.max(
              delay * CONFIG.timeMulInc, delay + CONFIG.timeMinInc
            ), CONFIG.timeCap
          );
          this.monitor(ref, token, cb, errCb, newDelay);
        }, delay);
      } else {
        this.changeStatus(false, false);
      }
    });
  } // monitor

  _cancel(ref, cb) {
    if (!(ref in this._tokens && this._tokens[ref] >= 0)) return;
    const token = this._tokens[ref];
    const url = this._urls[ref];
    const obj = JSON.stringify({
      action: 'stop',
      token: token,
    });
    this._tokens[ref] = -1;
    this._urls[ref] = null;
    this.sendRequest(url, obj, (err, data) => {
      if (err) {
        return cb(err);
      }
      return cb(+data['token'] !== token && {
        err: `token mismatch: ${data['token']} instead of ${token}`,
      });
    });
  } // _cancel

  execute(cb, data) {
    let err = true;
    try {
      cb(data);
      err = false;
    } finally {
      if (err) {
        this.changeStatus(false, true);
      } else {
        this.changeStatus(false, false);
      }
    }
  } // execute

  post(ref, url, payload, cb, errCb) {
    if (!this._active) return;
    this._starts[ref] = {
      url: url,
      cb: cb,
      errCb: errCb,
      payload: payload,
    };
    this.postTask(ref);
  } // post

  cancel(ref) {
    this._cancel(ref, (err) => {
      this.changeStatus(false, !!err);
      if (err) {
        console.warn(`Failed to cancel ${ref}`);
        return console.warn(err);
      }
    });
  } // cancel
} // Worker

window.Worker = Worker;
