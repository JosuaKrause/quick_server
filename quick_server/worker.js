/**
 * !!! This file can be found as worker.js in the quick_server folder !!!
 *
 * Provides worker oriented networking interface.
 *
 * Created by krause on 2016-06-22.
 */

export const CONFIG = {
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
export const VERSION = '0.7.12';

export class Worker {
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

export class VariablePool {
  constructor(worker, objectPath) {
    this._worker = worker;
    this._objectPath = objectPath;
    this._curQuery = {};
    this._variables = {};
    this._count = 0;
    this._timer = null;
  }

  executeQuery() {
    const query = this._curQuery;
    if(Object.keys(query).length === 0) return;
    const count = this._count;
    this._curQuery = {};
    this._count += 1;
    this._worker.post(`query${count}`, this._objectPath, {
      "query": query,
    }, (data) => {
      this._applyValues(this._variables, data, []);
    });
  }

  _queueQuery(chg) {
    if(!chg) return;
    if(this._timer !== null) return;
    this._timer = setTimeout(() => {
      this.executeQuery();
      this._timer = null;
    }, 1);
  }

  _applyValues(vars, data, path) {
    Object.keys(data).forEach((k) => {
      const d = data[k];
      if("map" in d) {
        if(!(k in vars)) {
          vars[k] = new WeakMap();
        }
        Object.keys(d.map).forEach((innerK) => {
          if(!(innerK in vars[k])) {
            vars[k][innerK] = {};
          }
          this._applyValues(vars[k][innerK], d.map[innerK], path + [k, innerK]);
        });
      } else if("value" in d) {
        vars[k] = Object.seal(new Variable(this, path + [k], true, d.value));
      } else {
        console.warn("incorrect response", d);
        throw new Error("internal error")
      }
    });
  }

  _addAction(qobj, path, type, value) {
    if(path.length >= 2) {
      const key = path[0];
      if(!(key in qobj)) {
        qobj[key] = {
          "type": "get",
          "queries": {},
        };
      } else if(!("queries" in qobj[key])) {
        qobj[key]["queries"] = {};
      }
      const kname = path[1];
      if(!(kname in qobj[key]["queries"])) {
        qobj[key]["queries"][kname] = {};
      }
      return this._addAction(
        qobj[key]["queries"][kname], path.slice(2), type, value);
    }
    const name = path[0];
    if(!(name in qobj)) {
      qobj[name] = {};
    } else {
      if(qobj[name]["type"] === "set" && type !== "set") {
        return false;
      }
    }
    if(type !== "get" && type !== "set") {
      throw new Error(`invalid type: ${type}`);
    }
    qobj[name]["type"] = type;
    if(type === "set") {
      qobj[name]["value"] = value;
    }
    return true;
  }

  addGetAction(path) {
    const chg = this._addAction(this._curQuery, path, "get", undefined);
    this._queueQuery(chg);
  }

  addSetAction(path, value) {
    const chg = this._addAction(this._curQuery, path, "set", value);
    this._queueQuery(chg);
  }

  getValue(path) {
    const full = path.slice();
    let vars = this._variables;
    while(path.length > 1) {
      const mapName = path.shift();
      const key = path.shift();
      if(!(mapName in vars)) {
        vars[mapName] = new WeakMap();
      }
      if(!(key in vars[mapName][key])) {
        vars[mapName][key] = {};
      }
      vars = vars[mapName][key];
    }
    if(!path.length) {
      throw new Error(`expected longer path: ${full}`);
    }
    const name = path.shift();
    if(!(name in vars)) {
      vars[name] = Object.seal(new Variable(this, full, false, null));
    }
    return vars[name];
  }
} // VariablePool

class Variable {
  constructor(pool, path, sync, value) {
    this._pool = pool;
    this._path = path;
    this._sync = sync;
    this._value = value;
  }

  update() {
    this._pool.addGetAction(this._path);
  }

  has() {
    if(!this._sync) {
      this.update();
    }
    return this._sync;
  }

  get value() {
    if(!this.has()) {
      throw new Error("variable not in sync");
    }
    return this._value;
  }

  set value(val) {
    this._pool.addSetAction(this._path, val);
  }
} // Variable

// *** FIXME Experimental React API for direct object access. ***
export let IOProvider = null;
export let withIO = null;
try {
  import('react').then((React) => {
    const { Provider, Consumer } = React.createContext(undefined);

    class IOProviderRaw extends React.PureComponent {
      constructor(props) {
        super(props);
        this.state = {
          pool: null,
        };
      }

      componentWillMount() {
        this.propsToState({}, this.props);
      }

      componentWillReceiveProps(nextProps) {
        this.propsToState(this.props, nextProps);
      }

      propsToState(props, nextProps) {
        const { objectPath="/objects/" } = nextProps;
        if(props.objectPath === objectPath) return;
        this.setState({
          pool: new VariablePool(new Worker(), objectPath),
        });
      }

      render() {
        const { children } = this.props;
        const { pool } = this.state;
        if(!pool) return null;
        return React.createElement(Provider, {
          value: pool,
        }, children);
      }
    } // IOProviderRaw
    IOProvider = IOProviderRaw;

    const withIORaw = (keys, component) => {
      return React.createElement(Consumer, {}, (pool) => {
        return function IOComponent(props) {
          const newProps = Object.assign({}, props);
          keys(props).forEach((k) => {
            newProps[k] = pool.getValue([k]);
          });
          return React.createElement(component, newProps, props.children);
        };
      });
    };
    withIO = withIORaw;
  });
} catch(e) {
  console.warn("react not found", e);
}
