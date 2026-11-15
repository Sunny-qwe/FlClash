(function (global) {
  // Env.js formats dates with RegExp.$1, which goja does not keep.
  const exec = RegExp.prototype.exec;
  const statics = ['$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8', '$9', 'lastMatch', 'input'];
  for (const name of statics) {
    Object.defineProperty(RegExp, name, { value: '', writable: true, configurable: true });
  }
  Object.defineProperty(RegExp.prototype, 'exec', {
    value: function (text) {
      const match = exec.call(this, text);
      if (match) {
        for (let i = 1; i <= 9; i++) RegExp['$' + i] = match[i] === undefined ? '' : match[i];
        RegExp.lastMatch = match[0];
        RegExp.input = String(text);
      }
      return match;
    },
    writable: true,
    configurable: true,
  });

  const encode = (text) => encodeURIComponent(text).replace(/%20/g, '+').replace(/[!'()~]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  const decode = (text) => {
    try {
      return decodeURIComponent(text.replace(/\+/g, ' '));
    } catch (e) {
      return text;
    }
  };

  class URLSearchParams {
    constructor(init) {
      this._list = [];
      this._url = null;
      if (init == null) return;
      if (typeof init === 'object') {
        if (init instanceof URLSearchParams) {
          this._list = init._list.map((pair) => pair.slice());
        } else if (typeof init[Symbol.iterator] === 'function') {
          for (const pair of init) this._list.push([String(pair[0]), String(pair[1])]);
        } else {
          for (const key of Object.keys(init)) this._list.push([key, String(init[key])]);
        }
        return;
      }
      this._parse(String(init));
    }
    _parse(text) {
      this._list = [];
      if (text.startsWith('?')) text = text.slice(1);
      for (const part of text.split('&')) {
        if (!part) continue;
        const at = part.indexOf('=');
        this._list.push(at < 0 ? [decode(part), ''] : [decode(part.slice(0, at)), decode(part.slice(at + 1))]);
      }
    }
    _changed() {
      if (this._url) {
        const query = this.toString();
        this._url._search = query ? '?' + query : '';
      }
    }
    append(key, value) {
      this._list.push([String(key), String(value)]);
      this._changed();
    }
    delete(key) {
      key = String(key);
      this._list = this._list.filter((pair) => pair[0] !== key);
      this._changed();
    }
    get(key) {
      key = String(key);
      const pair = this._list.find((pair) => pair[0] === key);
      return pair ? pair[1] : null;
    }
    getAll(key) {
      key = String(key);
      return this._list.filter((pair) => pair[0] === key).map((pair) => pair[1]);
    }
    has(key) {
      key = String(key);
      return this._list.some((pair) => pair[0] === key);
    }
    set(key, value) {
      key = String(key);
      value = String(value);
      const at = this._list.findIndex((pair) => pair[0] === key);
      if (at < 0) {
        this._list.push([key, value]);
      } else {
        this._list[at][1] = value;
        this._list = this._list.filter((pair, i) => i <= at || pair[0] !== key);
      }
      this._changed();
    }
    sort() {
      this._list.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      this._changed();
    }
    forEach(callback, thisArg) {
      for (const [key, value] of this._list) callback.call(thisArg, value, key, this);
    }
    keys() {
      return this._list.map((pair) => pair[0])[Symbol.iterator]();
    }
    values() {
      return this._list.map((pair) => pair[1])[Symbol.iterator]();
    }
    entries() {
      return this._list.map((pair) => [pair[0], pair[1]])[Symbol.iterator]();
    }
    [Symbol.iterator]() {
      return this.entries();
    }
    get size() {
      return this._list.length;
    }
    toString() {
      return this._list.map((pair) => encode(pair[0]) + '=' + encode(pair[1])).join('&');
    }
  }

  const defaultPorts = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443', 'ftp:': '21' };
  const pattern = /^([a-zA-Z][a-zA-Z0-9+.-]*:)(?:\/\/(?:([^:@\/?#]*)(?::([^@\/?#]*))?@)?(\[[^\]]*\]|[^:\/?#]*)(?::(\d*))?)?([^?#]*)(\?[^#]*)?(#.*)?$/;

  const removeDots = (path) => {
    const out = [];
    for (const segment of path.split('/')) {
      if (segment === '..') {
        if (out.length > 1) out.pop();
      } else if (segment !== '.') {
        out.push(segment);
      }
    }
    if (/\/\.\.?$/.test(path)) out.push('');
    return out.join('/');
  };

  const resolve = (text, base) => {
    if (pattern.test(text) && /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(text)) return text;
    const parent = new URL(base);
    if (text.startsWith('//')) return parent.protocol + text;
    const origin = parent.protocol + '//' + (parent.username ? parent.username + (parent.password ? ':' + parent.password : '') + '@' : '') + parent.host;
    if (text.startsWith('/')) return origin + removeDots(text);
    if (text.startsWith('?')) return origin + parent.pathname + text;
    if (text.startsWith('#')) return origin + parent.pathname + parent.search + text;
    if (text === '') return origin + parent.pathname + parent.search;
    const directory = parent.pathname.slice(0, parent.pathname.lastIndexOf('/') + 1);
    return origin + removeDots(directory + text);
  };

  class URL {
    constructor(url, base) {
      let text = String(url).trim();
      if (base !== undefined) text = resolve(text, String(base));
      const match = pattern.exec(text);
      if (!match || (match[4] === undefined && /^(https?|wss?|ftp):$/i.test(match[1]))) {
        throw new TypeError('Invalid URL: ' + url);
      }
      this._protocol = match[1].toLowerCase();
      const special = this._protocol in defaultPorts;
      this._username = match[2] || '';
      this._password = match[3] || '';
      this._hostname = special ? (match[4] || '').toLowerCase() : match[4] || '';
      this._port = match[5] && match[5] !== defaultPorts[this._protocol] ? match[5] : '';
      this._pathname = match[6] ? (special ? removeDots(match[6]) : match[6]) : special ? '/' : '';
      this._search = match[7] && match[7] !== '?' ? match[7] : '';
      this._hash = match[8] && match[8] !== '#' ? match[8] : '';
      this._params = new URLSearchParams(this._search);
      this._params._url = this;
    }
    get protocol() {
      return this._protocol;
    }
    set protocol(value) {
      this._protocol = String(value).replace(/:?$/, ':').toLowerCase();
    }
    get username() {
      return this._username;
    }
    set username(value) {
      this._username = String(value);
    }
    get password() {
      return this._password;
    }
    set password(value) {
      this._password = String(value);
    }
    get hostname() {
      return this._hostname;
    }
    set hostname(value) {
      this._hostname = String(value);
    }
    get port() {
      return this._port;
    }
    set port(value) {
      value = String(value);
      this._port = value === defaultPorts[this._protocol] ? '' : value;
    }
    get host() {
      return this._hostname + (this._port ? ':' + this._port : '');
    }
    set host(value) {
      const [hostname, port] = String(value).split(':');
      this._hostname = hostname;
      if (port !== undefined) this.port = port;
    }
    get origin() {
      return this._protocol + '//' + this.host;
    }
    get pathname() {
      return this._pathname;
    }
    set pathname(value) {
      value = String(value);
      this._pathname = value.startsWith('/') ? value : '/' + value;
    }
    get search() {
      return this._search;
    }
    set search(value) {
      value = String(value);
      this._search = value && value !== '?' ? (value.startsWith('?') ? value : '?' + value) : '';
      this._params._parse(this._search);
    }
    get searchParams() {
      return this._params;
    }
    get hash() {
      return this._hash;
    }
    set hash(value) {
      value = String(value);
      this._hash = value && value !== '#' ? (value.startsWith('#') ? value : '#' + value) : '';
    }
    get href() {
      const credentials = this._username ? this._username + (this._password ? ':' + this._password : '') + '@' : '';
      return this._protocol + '//' + credentials + this.host + this._pathname + this._search + this._hash;
    }
    set href(value) {
      Object.assign(this, new URL(value));
      this._params._url = this;
    }
    toString() {
      return this.href;
    }
    toJSON() {
      return this.href;
    }
  }

  global.URL = URL;
  global.URLSearchParams = URLSearchParams;
})(globalThis);
