(function(e, a) { for(var i in a) e[i] = a[i]; }(exports, /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

const stripe = __webpack_require__(15)('sk_test_V816yh3aCvg1JK0w16EkwiMs00eeWxmLBD');

exports.handler = (() => {
  var _ref = _asyncToGenerator(function* (event) {
    try {
      console.log(event);
      console.log(event.body);
      const { tokenId, email, name, description, amount } = JSON.parse(event.body);

      const customer = yield stripe.customers.create({
        description: email,
        source: tokenId
      });

      const data = yield stripe.charges.create({
        customer: customer.id,
        amount,
        name,
        description,
        currency: 'usd'
      });

      return {
        statusCode: 200,
        body: JSON.stringify(data)
      };
    } catch (error) {
      console.log(err);
      return {
        statusCode: 500,
        body: err.message
      };
    }
  });

  return function (_x) {
    return _ref.apply(this, arguments);
  };
})();

/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var http = __webpack_require__(6);
var https = __webpack_require__(23);
var path = __webpack_require__(24);
var uuid = __webpack_require__(25);

var utils = __webpack_require__(2);
var Error = __webpack_require__(3);

var hasOwn = {}.hasOwnProperty;

var defaultHttpAgent = new http.Agent({keepAlive: true});
var defaultHttpsAgent = new https.Agent({keepAlive: true});

// Provide extension mechanism for Stripe Resource Sub-Classes
StripeResource.extend = utils.protoExtend;

// Expose method-creator & prepared (basic) methods
StripeResource.method = __webpack_require__(12);
StripeResource.BASIC_METHODS = __webpack_require__(29);

StripeResource.MAX_BUFFERED_REQUEST_METRICS = 100;

/**
 * Encapsulates request logic for a Stripe Resource
 */
function StripeResource(stripe, urlData) {
  this._stripe = stripe;
  this._urlData = urlData || {};

  this.basePath = utils.makeURLInterpolator(this.basePath || stripe.getApiField('basePath'));
  this.resourcePath = this.path;
  this.path = utils.makeURLInterpolator(this.path);

  if (this.includeBasic) {
    this.includeBasic.forEach(function(methodName) {
      this[methodName] = StripeResource.BASIC_METHODS[methodName];
    }, this);
  }

  this.initialize.apply(this, arguments);
}

StripeResource.prototype = {

  path: '',

  // Methods that don't use the API's default '/v1' path can override it with this setting.
  basePath: null,

  initialize: function() {},

  // Function to override the default data processor. This allows full control
  // over how a StripeResource's request data will get converted into an HTTP
  // body. This is useful for non-standard HTTP requests. The function should
  // take method name, data, and headers as arguments.
  requestDataProcessor: null,

  // Function to add a validation checks before sending the request, errors should
  // be thrown, and they will be passed to the callback/promise.
  validateRequest: null,

  createFullPath: function(commandPath, urlData) {
    return path.join(
      this.basePath(urlData),
      this.path(urlData),
      typeof commandPath == 'function' ?
        commandPath(urlData) : commandPath
    ).replace(/\\/g, '/'); // ugly workaround for Windows
  },

  // Creates a relative resource path with symbols left in (unlike
  // createFullPath which takes some data to replace them with). For example it
  // might produce: /invoices/{id}
  createResourcePathWithSymbols: function(pathWithSymbols) {
    return '/' + path.join(
      this.resourcePath,
      pathWithSymbols || ''
    ).replace(/\\/g, '/'); // ugly workaround for Windows
  },

  createUrlData: function() {
    var urlData = {};
    // Merge in baseData
    for (var i in this._urlData) {
      if (hasOwn.call(this._urlData, i)) {
        urlData[i] = this._urlData[i];
      }
    }
    return urlData;
  },

  // DEPRECATED: Here for backcompat in case users relied on this.
  wrapTimeout: utils.callbackifyPromiseWithTimeout,

  _timeoutHandler: function(timeout, req, callback) {
    var self = this;
    return function() {
      var timeoutErr = new Error('ETIMEDOUT');
      timeoutErr.code = 'ETIMEDOUT';

      req._isAborted = true;
      req.abort();

      callback.call(
        self,
        new Error.StripeConnectionError({
          message: 'Request aborted due to timeout being reached (' + timeout + 'ms)',
          detail: timeoutErr,
        }),
        null
      );
    }
  },

  _responseHandler: function(req, callback) {
    var self = this;
    return function(res) {
      var response = '';

      res.setEncoding('utf8');
      res.on('data', function(chunk) {
        response += chunk;
      });
      res.on('end', function() {
        var headers = res.headers || {};
        // NOTE: Stripe responds with lowercase header names/keys.

        // For convenience, make Request-Id easily accessible on
        // lastResponse.
        res.requestId = headers['request-id'];

        var requestDurationMs = Date.now() - req._requestStart;

        var responseEvent = utils.removeEmpty({
          api_version: headers['stripe-version'],
          account: headers['stripe-account'],
          idempotency_key: headers['idempotency-key'],
          method: req._requestEvent.method,
          path: req._requestEvent.path,
          status: res.statusCode,
          request_id: res.requestId,
          elapsed: requestDurationMs,
        });

        self._stripe._emitter.emit('response', responseEvent);

        try {
          response = JSON.parse(response);

          if (response.error) {
            var err;

            // Convert OAuth error responses into a standard format
            // so that the rest of the error logic can be shared
            if (typeof response.error === 'string') {
              response.error = {
                type: response.error,
                message: response.error_description
              }
            }

            response.error.headers = headers;
            response.error.statusCode = res.statusCode;
            response.error.requestId = res.requestId;

            if (res.statusCode === 401) {
              err = new Error.StripeAuthenticationError(response.error);
            } else if (res.statusCode === 403) {
              err = new Error.StripePermissionError(response.error);
            } else if (res.statusCode === 429) {
              err = new Error.StripeRateLimitError(response.error);
            } else {
              err = Error.StripeError.generate(response.error);
            }
            return callback.call(self, err, null);
          }
        } catch (e) {
          return callback.call(
            self,
            new Error.StripeAPIError({
              message: 'Invalid JSON received from the Stripe API',
              response: response,
              exception: e,
              requestId: headers['request-id'],
            }),
            null
          );
        }

        self._recordRequestMetrics(res.requestId, requestDurationMs);

        // Expose res object
        Object.defineProperty(response, 'lastResponse', {
          enumerable: false,
          writable: false,
          value: res,
        });
        callback.call(self, null, response);
      });
    };
  },

  _generateConnectionErrorMessage: function(requestRetries) {
    return 'An error occurred with our connection to Stripe.' + (requestRetries > 0 ? ' Request was retried ' + requestRetries + ' times.' : '');
  },

  _errorHandler: function(req, requestRetries, callback) {
    var self = this;
    return function(error) {
      if (req._isAborted) {
        // already handled
        return;
      }
      callback.call(
        self,
        new Error.StripeConnectionError({
          message: self._generateConnectionErrorMessage(requestRetries),
          detail: error,
        }),
        null
      );
    }
  },

  _shouldRetry: function(res, numRetries) {
    // Do not retry if we are out of retries.
    if (numRetries >= this._stripe.getMaxNetworkRetries()) {
      return false;
    }

    // Retry on connection error.
    if (!res) {
      return true;
    }

    // Retry on conflict and availability errors.
    if (res.statusCode === 409 || res.statusCode === 503) {
      return true;
    }

    // Retry on 5xx's, except POST's, which our idempotency framework
    // would just replay as 500's again anyway.
    if (res.statusCode >= 500 && res.req._requestEvent.method !== 'POST') {
      return true;
    }

    return false;
  },

  _getSleepTimeInMS: function(numRetries) {
    var initialNetworkRetryDelay = this._stripe.getInitialNetworkRetryDelay();
    var maxNetworkRetryDelay = this._stripe.getMaxNetworkRetryDelay();

    // Apply exponential backoff with initialNetworkRetryDelay on the
    // number of numRetries so far as inputs. Do not allow the number to exceed
    // maxNetworkRetryDelay.
    var sleepSeconds = Math.min(
      initialNetworkRetryDelay * Math.pow(numRetries - 1, 2),
      maxNetworkRetryDelay
    );

    // Apply some jitter by randomizing the value in the range of
    // (sleepSeconds / 2) to (sleepSeconds).
    sleepSeconds *= 0.5 * (1 + Math.random());

    // But never sleep less than the base sleep seconds.
    sleepSeconds = Math.max(initialNetworkRetryDelay, sleepSeconds);

    return sleepSeconds * 1000;
  },

  _defaultHeaders: function(auth, contentLength, apiVersion) {
    var userAgentString = 'Stripe/v1 NodeBindings/' + this._stripe.getConstant('PACKAGE_VERSION');

    if (this._stripe._appInfo) {
      userAgentString += ' ' + this._stripe.getAppInfoAsString();
    }

    var headers = {
      // Use specified auth token or use default from this stripe instance:
      'Authorization': auth ?
        'Bearer ' + auth :
        this._stripe.getApiField('auth'),
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': contentLength,
      'User-Agent': userAgentString,
    };

    if (apiVersion) {
      headers['Stripe-Version'] = apiVersion;
    }

    return headers;
  },

  _addTelemetryHeader: function(headers) {
    if (this._stripe.getTelemetryEnabled() && this._stripe._prevRequestMetrics.length > 0) {
      var metrics = this._stripe._prevRequestMetrics.shift();
      headers['X-Stripe-Client-Telemetry'] = JSON.stringify({
        'last_request_metrics': metrics
      });
    }
  },

  _recordRequestMetrics: function(requestId, requestDurationMs) {
    if (this._stripe.getTelemetryEnabled() && requestId) {
      if (this._stripe._prevRequestMetrics.length > StripeResource.MAX_BUFFERED_REQUEST_METRICS) {
        utils.emitWarning('Request metrics buffer is full, dropping telemetry message.');
      } else {
        this._stripe._prevRequestMetrics.push({
          'request_id': requestId,
          'request_duration_ms': requestDurationMs,
        });
      }
    }
  },

  _request: function(method, host, path, data, auth, options, callback) {
    var self = this;
    var requestData;

    function makeRequestWithData(error, data) {
      var apiVersion;
      var headers;

      if (error) {
        return callback(error);
      }

      apiVersion = self._stripe.getApiField('version');
      requestData = data;
      headers = self._defaultHeaders(auth, requestData.length, apiVersion);

      self._stripe.getClientUserAgent(function(cua) {
        headers['X-Stripe-Client-User-Agent'] = cua;

        if (options.headers) {
          Object.assign(headers, options.headers);
        }

        self._addTelemetryHeader(headers);

        makeRequest(apiVersion, headers);
      });
    }

    if (self.requestDataProcessor) {
      self.requestDataProcessor(method, data, options.headers, makeRequestWithData);
    } else {
      makeRequestWithData(null, utils.stringifyRequestData(data || {}));
    }

    function retryRequest(requestFn, apiVersion, headers, requestRetries) {
      requestRetries += 1;

      return setTimeout(
        requestFn,
        self._getSleepTimeInMS(requestRetries),
        apiVersion,
        headers,
        requestRetries
      );
    }

    function makeRequest(apiVersion, headers, numRetries) {
      var timeout = self._stripe.getApiField('timeout');
      var isInsecureConnection = self._stripe.getApiField('protocol') == 'http';
      var agent = self._stripe.getApiField('agent');
      if (agent == null) {
        agent = isInsecureConnection ? defaultHttpAgent : defaultHttpsAgent;
      }

      var req = (
        isInsecureConnection ? http : https
      ).request({
        host: host || self._stripe.getApiField('host'),
        port: self._stripe.getApiField('port'),
        path: path,
        method: method,
        agent: agent,
        headers: headers,
        ciphers: 'DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2:!MD5',
      });

      // If this is a POST and we allow multiple retries, set a idempotency key if one is not
      // already provided.
      if (method === 'POST' && self._stripe.getMaxNetworkRetries() > 0) {
        if (!headers.hasOwnProperty('Idempotency-Key')) {
          headers['Idempotency-Key'] = uuid();
        }
      }

      var requestEvent = utils.removeEmpty({
        api_version: apiVersion,
        account: headers['Stripe-Account'],
        idempotency_key: headers['Idempotency-Key'],
        method: method,
        path: path,
      });

      var requestRetries = numRetries || 0;

      req._requestEvent = requestEvent;

      req._requestStart = Date.now();

      self._stripe._emitter.emit('request', requestEvent);

      req.setTimeout(timeout, self._timeoutHandler(timeout, req, callback));

      req.on('response', function(res) {
        if (self._shouldRetry(res, requestRetries)) {
          return retryRequest(makeRequest, apiVersion, headers, requestRetries);
        } else {
          return self._responseHandler(req, callback)(res);
        }
      });

      req.on('error', function(error) {
        if (self._shouldRetry(null, requestRetries)) {
          return retryRequest(makeRequest, apiVersion, headers, requestRetries);
        } else {
          return self._errorHandler(req, requestRetries, callback)(error);
        }
      });

      req.on('socket', function(socket) {
        if (socket.connecting) {
          socket.on((isInsecureConnection ? 'connect' : 'secureConnect'), function() {
            // Send payload; we're safe:
            req.write(requestData);
            req.end();
          });
        } else {
          // we're already connected
          req.write(requestData);
          req.end();
        }
      });
    }
  },
};

module.exports = StripeResource;


/***/ }),
/* 2 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Buffer = __webpack_require__(4).Buffer;
var EventEmitter = __webpack_require__(7).EventEmitter;
var exec = __webpack_require__(18).exec;
var qs = __webpack_require__(19);
var crypto = __webpack_require__(5);

var hasOwn = {}.hasOwnProperty;
var isPlainObject = __webpack_require__(10);

var OPTIONS_KEYS = ['api_key', 'idempotency_key', 'stripe_account', 'stripe_version'];

var utils = module.exports = {

  isAuthKey: function(key) {
    return typeof key == 'string' && /^(?:[a-z]{2}_)?[A-z0-9]{32}$/.test(key);
  },

  isOptionsHash: function(o) {
    return isPlainObject(o) && OPTIONS_KEYS.some(function(key) {
      return hasOwn.call(o, key);
    });
  },

  /**
   * Stringifies an Object, accommodating nested objects
   * (forming the conventional key 'parent[child]=value')
   */
  stringifyRequestData: function(data) {
    return qs.stringify(data, {serializeDate: function (d) { return Math.floor(d.getTime() / 1000); }})
      // Don't use strict form encoding by changing the square bracket control
      // characters back to their literals. This is fine by the server, and
      // makes these parameter strings easier to read.
      .replace(/%5B/g, '[').replace(/%5D/g, ']');
  },

  /**
   * Outputs a new function with interpolated object property values.
   * Use like so:
   *   var fn = makeURLInterpolator('some/url/{param1}/{param2}');
   *   fn({ param1: 123, param2: 456 }); // => 'some/url/123/456'
   */
  makeURLInterpolator: (function() {
    var rc = {
      '\n': '\\n', '\"': '\\\"',
      '\u2028': '\\u2028', '\u2029': '\\u2029',
    };
    return function makeURLInterpolator(str) {
      var cleanString = str.replace(/["\n\r\u2028\u2029]/g, function($0) {
        return rc[$0];
      });
      return function(outputs) {
        return cleanString.replace(/\{([\s\S]+?)\}/g, function($0, $1) {
          return encodeURIComponent(outputs[$1] || '');
        });
      };
    };
  }()),

  /**
   * Return the data argument from a list of arguments
   */
  getDataFromArgs: function(args) {
    if (args.length < 1 || !isPlainObject(args[0])) {
      return {};
    }

    if (!utils.isOptionsHash(args[0])) {
      return args.shift();
    }

    var argKeys = Object.keys(args[0]);

    var optionKeysInArgs = argKeys.filter(function(key) {
      return OPTIONS_KEYS.indexOf(key) > -1;
    });

    // In some cases options may be the provided as the first argument.
    // Here we're detecting a case where there are two distinct arguments
    // (the first being args and the second options) and with known
    // option keys in the first so that we can warn the user about it.
    if (optionKeysInArgs.length > 0 && optionKeysInArgs.length !== argKeys.length) {
      emitWarning(
        'Options found in arguments (' + optionKeysInArgs.join(', ') + '). Did you mean to pass an options ' +
        'object? See https://github.com/stripe/stripe-node/wiki/Passing-Options.'
      );
    }

    return {};
  },

  /**
   * Return the options hash from a list of arguments
   */
  getOptionsFromArgs: function(args) {
    var opts = {
      auth: null,
      headers: {},
    };
    if (args.length > 0) {
      var arg = args[args.length - 1];
      if (utils.isAuthKey(arg)) {
        opts.auth = args.pop();
      } else if (utils.isOptionsHash(arg)) {
        var params = args.pop();

        var extraKeys = Object.keys(params).filter(function(key) {
          return OPTIONS_KEYS.indexOf(key) == -1;
        });

        if (extraKeys.length) {
          emitWarning('Invalid options found (' + extraKeys.join(', ') + '); ignoring.');
        }

        if (params.api_key) {
          opts.auth = params.api_key;
        }
        if (params.idempotency_key) {
          opts.headers['Idempotency-Key'] = params.idempotency_key;
        }
        if (params.stripe_account) {
          opts.headers['Stripe-Account'] = params.stripe_account;
        }
        if (params.stripe_version) {
          opts.headers['Stripe-Version'] = params.stripe_version;
        }
      }
    }
    return opts;
  },

  /**
   * Provide simple "Class" extension mechanism
   */
  protoExtend: function(sub) {
    var Super = this;
    var Constructor = hasOwn.call(sub, 'constructor') ? sub.constructor : function() {
      Super.apply(this, arguments);
    };

    // This initialization logic is somewhat sensitive to be compatible with
    // divergent JS implementations like the one found in Qt. See here for more
    // context:
    //
    // https://github.com/stripe/stripe-node/pull/334
    Object.assign(Constructor, Super);
    Constructor.prototype = Object.create(Super.prototype);
    Object.assign(Constructor.prototype, sub);

    return Constructor;
  },

  /**
  * Secure compare, from https://github.com/freewil/scmp
  */
  secureCompare: function(a, b) {
    a = Buffer.from(a);
    b = Buffer.from(b);

    // return early here if buffer lengths are not equal since timingSafeEqual
    // will throw if buffer lengths are not equal
    if (a.length !== b.length) {
      return false;
    }

    // use crypto.timingSafeEqual if available (since Node.js v6.6.0),
    // otherwise use our own scmp-internal function.
    if (crypto.timingSafeEqual) {
      return crypto.timingSafeEqual(a, b);
    }

    var len = a.length;
    var result = 0;

    for (var i = 0; i < len; ++i) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  },

  /**
  * Remove empty values from an object
  */
  removeEmpty: function(obj) {
    if (typeof obj !== 'object') {
      throw new Error('Argument must be an object');
    }

    Object.keys(obj).forEach(function(key) {
      if (obj[key] === null || obj[key] === undefined) {
        delete obj[key];
      }
    });

    return obj;
  },

  /**
  * Determine if file data is a derivative of EventEmitter class.
  * https://nodejs.org/api/events.html#events_events
  */
  checkForStream: function (obj) {
    if (obj.file && obj.file.data) {
      return obj.file.data instanceof EventEmitter;
    }
    return false;
  },

  callbackifyPromiseWithTimeout: function(promise, callback) {
    if (callback) {
      // Ensure callback is called outside of promise stack.
      return promise.then(function(res) {
        setTimeout(function() { callback(null, res) }, 0);
      }, function(err) {
        setTimeout(function() { callback(err, null); }, 0);
      });
    }

    return promise;
  },

  /**
   * Allow for special capitalization cases (such as OAuth)
   */
  pascalToCamelCase: function(name) {
    if (name === 'OAuth') {
      return 'oauth';
    } else {
      return name[0].toLowerCase() + name.substring(1);
    }
  },

  emitWarning: emitWarning,

  /**
   * Node's built in `exec` function sometimes throws outright,
   * and sometimes has a callback with an error,
   * depending on the type of error.
   *
   * This unifies that interface.
   */
  safeExec: function safeExec(cmd, cb) {
    try {
      utils._exec(cmd, cb);
    } catch (e) {
      cb(e, null);
    }
  },

  // For mocking in tests.
  _exec: exec,

  isObject: function isObject(obj) {
    var type = typeof obj;
    return (type === 'function' || type === 'object') && !!obj;
  },

  // For use in multipart requests
  flattenAndStringify: function flattenAndStringify(data) {
    var result = {};

    function step(obj, prevKey) {
      Object.keys(obj).forEach(function (key) {
        var value = obj[key];

        var newKey = prevKey ? `${prevKey}[${key}]` : key;

        if (utils.isObject(value)) {
          if (!Buffer.isBuffer(value) && !value.hasOwnProperty('data')) {
            // Non-buffer non-file Objects are recursively flattened
            return step(value, newKey);
          } else {
            // Buffers and file objects are stored without modification
            result[newKey] = value;
          }
        } else {
          // Primitives are converted to strings
          result[newKey] = String(value);
        }
      })
    }

    step(data);

    return result;
  },
};

function emitWarning(warning) {
  if (typeof process.emitWarning !== 'function') {
    return console.warn('Stripe: ' + warning); /* eslint-disable-line no-console */
  }

  return process.emitWarning(warning, 'Stripe');
}


/***/ }),
/* 3 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(2);

module.exports = _Error;

/**
 * Generic Error klass to wrap any errors returned by stripe-node
 */
function _Error(raw) {
  this.populate.apply(this, arguments);
  this.stack = (new Error(this.message)).stack;
}

// Extend Native Error
_Error.prototype = Object.create(Error.prototype);

_Error.prototype.type = 'GenericError';
_Error.prototype.populate = function(type, message) {
  this.type = type;
  this.message = message;
};

_Error.extend = utils.protoExtend;

/**
 * Create subclass of internal Error klass
 * (Specifically for errors returned from Stripe's REST API)
 */
var StripeError = _Error.StripeError = _Error.extend({
  type: 'StripeError',
  populate: function(raw) {
    // Move from prototype def (so it appears in stringified obj)
    this.type = this.type;

    this.stack = (new Error(raw.message)).stack;
    this.rawType = raw.type;
    this.code = raw.code;
    this.param = raw.param;
    this.message = raw.message;
    this.detail = raw.detail;
    this.raw = raw;
    this.headers = raw.headers;
    this.requestId = raw.requestId;
    this.statusCode = raw.statusCode;
  },
});

/**
 * Helper factory which takes raw stripe errors and outputs wrapping instances
 */
StripeError.generate = function(rawStripeError) {
  switch (rawStripeError.type) {
  case 'card_error':
    return new _Error.StripeCardError(rawStripeError);
  case 'invalid_request_error':
    return new _Error.StripeInvalidRequestError(rawStripeError);
  case 'api_error':
    return new _Error.StripeAPIError(rawStripeError);
  case 'idempotency_error':
    return new _Error.StripeIdempotencyError(rawStripeError);
  case 'invalid_grant':
    return new _Error.StripeInvalidGrantError(rawStripeError);
  }
  return new _Error('Generic', 'Unknown Error');
};

// Specific Stripe Error types:
_Error.StripeCardError = StripeError.extend({type: 'StripeCardError'});
_Error.StripeInvalidRequestError = StripeError.extend({type: 'StripeInvalidRequestError'});
_Error.StripeAPIError = StripeError.extend({type: 'StripeAPIError'});
_Error.StripeAuthenticationError = StripeError.extend({type: 'StripeAuthenticationError'});
_Error.StripePermissionError = StripeError.extend({type: 'StripePermissionError'});
_Error.StripeRateLimitError = StripeError.extend({type: 'StripeRateLimitError'});
_Error.StripeConnectionError = StripeError.extend({type: 'StripeConnectionError'});
_Error.StripeSignatureVerificationError = StripeError.extend({type: 'StripeSignatureVerificationError'});
_Error.StripeIdempotencyError = StripeError.extend({type: 'StripeIdempotencyError'});
_Error.StripeInvalidGrantError = StripeError.extend({type: 'StripeInvalidGrantError'});


/***/ }),
/* 4 */
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable node/no-deprecated-api */
var buffer = __webpack_require__(17)
var Buffer = buffer.Buffer

// alternative to using Object.keys for old browsers
function copyProps (src, dst) {
  for (var key in src) {
    dst[key] = src[key]
  }
}
if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
  module.exports = buffer
} else {
  // Copy properties from require('buffer')
  copyProps(buffer, exports)
  exports.Buffer = SafeBuffer
}

function SafeBuffer (arg, encodingOrOffset, length) {
  return Buffer(arg, encodingOrOffset, length)
}

// Copy static methods from Buffer
copyProps(Buffer, SafeBuffer)

SafeBuffer.from = function (arg, encodingOrOffset, length) {
  if (typeof arg === 'number') {
    throw new TypeError('Argument must not be a number')
  }
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.alloc = function (size, fill, encoding) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  var buf = Buffer(size)
  if (fill !== undefined) {
    if (typeof encoding === 'string') {
      buf.fill(fill, encoding)
    } else {
      buf.fill(fill)
    }
  } else {
    buf.fill(0)
  }
  return buf
}

SafeBuffer.allocUnsafe = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return Buffer(size)
}

SafeBuffer.allocUnsafeSlow = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return buffer.SlowBuffer(size)
}


/***/ }),
/* 5 */
/***/ (function(module, exports) {

module.exports = require("crypto");

/***/ }),
/* 6 */
/***/ (function(module, exports) {

module.exports = require("http");

/***/ }),
/* 7 */
/***/ (function(module, exports) {

module.exports = require("events");

/***/ }),
/* 8 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var has = Object.prototype.hasOwnProperty;
var isArray = Array.isArray;

var hexTable = (function () {
    var array = [];
    for (var i = 0; i < 256; ++i) {
        array.push('%' + ((i < 16 ? '0' : '') + i.toString(16)).toUpperCase());
    }

    return array;
}());

var compactQueue = function compactQueue(queue) {
    while (queue.length > 1) {
        var item = queue.pop();
        var obj = item.obj[item.prop];

        if (isArray(obj)) {
            var compacted = [];

            for (var j = 0; j < obj.length; ++j) {
                if (typeof obj[j] !== 'undefined') {
                    compacted.push(obj[j]);
                }
            }

            item.obj[item.prop] = compacted;
        }
    }
};

var arrayToObject = function arrayToObject(source, options) {
    var obj = options && options.plainObjects ? Object.create(null) : {};
    for (var i = 0; i < source.length; ++i) {
        if (typeof source[i] !== 'undefined') {
            obj[i] = source[i];
        }
    }

    return obj;
};

var merge = function merge(target, source, options) {
    if (!source) {
        return target;
    }

    if (typeof source !== 'object') {
        if (isArray(target)) {
            target.push(source);
        } else if (target && typeof target === 'object') {
            if ((options && (options.plainObjects || options.allowPrototypes)) || !has.call(Object.prototype, source)) {
                target[source] = true;
            }
        } else {
            return [target, source];
        }

        return target;
    }

    if (!target || typeof target !== 'object') {
        return [target].concat(source);
    }

    var mergeTarget = target;
    if (isArray(target) && !isArray(source)) {
        mergeTarget = arrayToObject(target, options);
    }

    if (isArray(target) && isArray(source)) {
        source.forEach(function (item, i) {
            if (has.call(target, i)) {
                var targetItem = target[i];
                if (targetItem && typeof targetItem === 'object' && item && typeof item === 'object') {
                    target[i] = merge(targetItem, item, options);
                } else {
                    target.push(item);
                }
            } else {
                target[i] = item;
            }
        });
        return target;
    }

    return Object.keys(source).reduce(function (acc, key) {
        var value = source[key];

        if (has.call(acc, key)) {
            acc[key] = merge(acc[key], value, options);
        } else {
            acc[key] = value;
        }
        return acc;
    }, mergeTarget);
};

var assign = function assignSingleSource(target, source) {
    return Object.keys(source).reduce(function (acc, key) {
        acc[key] = source[key];
        return acc;
    }, target);
};

var decode = function (str, decoder, charset) {
    var strWithoutPlus = str.replace(/\+/g, ' ');
    if (charset === 'iso-8859-1') {
        // unescape never throws, no try...catch needed:
        return strWithoutPlus.replace(/%[0-9a-f]{2}/gi, unescape);
    }
    // utf-8
    try {
        return decodeURIComponent(strWithoutPlus);
    } catch (e) {
        return strWithoutPlus;
    }
};

var encode = function encode(str, defaultEncoder, charset) {
    // This code was originally written by Brian White (mscdex) for the io.js core querystring library.
    // It has been adapted here for stricter adherence to RFC 3986
    if (str.length === 0) {
        return str;
    }

    var string = typeof str === 'string' ? str : String(str);

    if (charset === 'iso-8859-1') {
        return escape(string).replace(/%u[0-9a-f]{4}/gi, function ($0) {
            return '%26%23' + parseInt($0.slice(2), 16) + '%3B';
        });
    }

    var out = '';
    for (var i = 0; i < string.length; ++i) {
        var c = string.charCodeAt(i);

        if (
            c === 0x2D // -
            || c === 0x2E // .
            || c === 0x5F // _
            || c === 0x7E // ~
            || (c >= 0x30 && c <= 0x39) // 0-9
            || (c >= 0x41 && c <= 0x5A) // a-z
            || (c >= 0x61 && c <= 0x7A) // A-Z
        ) {
            out += string.charAt(i);
            continue;
        }

        if (c < 0x80) {
            out = out + hexTable[c];
            continue;
        }

        if (c < 0x800) {
            out = out + (hexTable[0xC0 | (c >> 6)] + hexTable[0x80 | (c & 0x3F)]);
            continue;
        }

        if (c < 0xD800 || c >= 0xE000) {
            out = out + (hexTable[0xE0 | (c >> 12)] + hexTable[0x80 | ((c >> 6) & 0x3F)] + hexTable[0x80 | (c & 0x3F)]);
            continue;
        }

        i += 1;
        c = 0x10000 + (((c & 0x3FF) << 10) | (string.charCodeAt(i) & 0x3FF));
        out += hexTable[0xF0 | (c >> 18)]
            + hexTable[0x80 | ((c >> 12) & 0x3F)]
            + hexTable[0x80 | ((c >> 6) & 0x3F)]
            + hexTable[0x80 | (c & 0x3F)];
    }

    return out;
};

var compact = function compact(value) {
    var queue = [{ obj: { o: value }, prop: 'o' }];
    var refs = [];

    for (var i = 0; i < queue.length; ++i) {
        var item = queue[i];
        var obj = item.obj[item.prop];

        var keys = Object.keys(obj);
        for (var j = 0; j < keys.length; ++j) {
            var key = keys[j];
            var val = obj[key];
            if (typeof val === 'object' && val !== null && refs.indexOf(val) === -1) {
                queue.push({ obj: obj, prop: key });
                refs.push(val);
            }
        }
    }

    compactQueue(queue);

    return value;
};

var isRegExp = function isRegExp(obj) {
    return Object.prototype.toString.call(obj) === '[object RegExp]';
};

var isBuffer = function isBuffer(obj) {
    if (!obj || typeof obj !== 'object') {
        return false;
    }

    return !!(obj.constructor && obj.constructor.isBuffer && obj.constructor.isBuffer(obj));
};

var combine = function combine(a, b) {
    return [].concat(a, b);
};

module.exports = {
    arrayToObject: arrayToObject,
    assign: assign,
    combine: combine,
    compact: compact,
    decode: decode,
    encode: encode,
    isBuffer: isBuffer,
    isRegExp: isRegExp,
    merge: merge
};


/***/ }),
/* 9 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var replace = String.prototype.replace;
var percentTwenties = /%20/g;

module.exports = {
    'default': 'RFC3986',
    formatters: {
        RFC1738: function (value) {
            return replace.call(value, percentTwenties, '+');
        },
        RFC3986: function (value) {
            return value;
        }
    },
    RFC1738: 'RFC1738',
    RFC3986: 'RFC3986'
};


/***/ }),
/* 10 */
/***/ (function(module, exports) {

/**
 * lodash (Custom Build) <https://lodash.com/>
 * Build: `lodash modularize exports="npm" -o ./`
 * Copyright jQuery Foundation and other contributors <https://jquery.org/>
 * Released under MIT license <https://lodash.com/license>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 */

/** `Object#toString` result references. */
var objectTag = '[object Object]';

/**
 * Checks if `value` is a host object in IE < 9.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a host object, else `false`.
 */
function isHostObject(value) {
  // Many host objects are `Object` objects that can coerce to strings
  // despite having improperly defined `toString` methods.
  var result = false;
  if (value != null && typeof value.toString != 'function') {
    try {
      result = !!(value + '');
    } catch (e) {}
  }
  return result;
}

/**
 * Creates a unary function that invokes `func` with its argument transformed.
 *
 * @private
 * @param {Function} func The function to wrap.
 * @param {Function} transform The argument transform.
 * @returns {Function} Returns the new function.
 */
function overArg(func, transform) {
  return function(arg) {
    return func(transform(arg));
  };
}

/** Used for built-in method references. */
var funcProto = Function.prototype,
    objectProto = Object.prototype;

/** Used to resolve the decompiled source of functions. */
var funcToString = funcProto.toString;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/** Used to infer the `Object` constructor. */
var objectCtorString = funcToString.call(Object);

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/7.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/** Built-in value references. */
var getPrototype = overArg(Object.getPrototypeOf, Object);

/**
 * Checks if `value` is object-like. A value is object-like if it's not `null`
 * and has a `typeof` result of "object".
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
 * @example
 *
 * _.isObjectLike({});
 * // => true
 *
 * _.isObjectLike([1, 2, 3]);
 * // => true
 *
 * _.isObjectLike(_.noop);
 * // => false
 *
 * _.isObjectLike(null);
 * // => false
 */
function isObjectLike(value) {
  return !!value && typeof value == 'object';
}

/**
 * Checks if `value` is a plain object, that is, an object created by the
 * `Object` constructor or one with a `[[Prototype]]` of `null`.
 *
 * @static
 * @memberOf _
 * @since 0.8.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a plain object, else `false`.
 * @example
 *
 * function Foo() {
 *   this.a = 1;
 * }
 *
 * _.isPlainObject(new Foo);
 * // => false
 *
 * _.isPlainObject([1, 2, 3]);
 * // => false
 *
 * _.isPlainObject({ 'x': 0, 'y': 0 });
 * // => true
 *
 * _.isPlainObject(Object.create(null));
 * // => true
 */
function isPlainObject(value) {
  if (!isObjectLike(value) ||
      objectToString.call(value) != objectTag || isHostObject(value)) {
    return false;
  }
  var proto = getPrototype(value);
  if (proto === null) {
    return true;
  }
  var Ctor = hasOwnProperty.call(proto, 'constructor') && proto.constructor;
  return (typeof Ctor == 'function' &&
    Ctor instanceof Ctor && funcToString.call(Ctor) == objectCtorString);
}

module.exports = isPlainObject;


/***/ }),
/* 11 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  // Since path can either be `account` or `accounts`, support both through stripeMethod path

  create: stripeMethod({
    method: 'POST',
    path: 'accounts',
  }),

  list: stripeMethod({
    method: 'GET',
    path: 'accounts',
    methodType: 'list',
  }),

  update: stripeMethod({
    method: 'POST',
    path: 'accounts/{id}',
    urlParams: ['id'],
  }),

  // Avoid 'delete' keyword in JS
  del: stripeMethod({
    method: 'DELETE',
    path: 'accounts/{id}',
    urlParams: ['id'],
  }),

  reject: stripeMethod({
    method: 'POST',
    path: 'accounts/{id}/reject',
    urlParams: ['id'],
  }),

  retrieve: function(id) {
    // No longer allow an api key to be passed as the first string to this function due to ambiguity between
    // old account ids and api keys. To request the account for an api key, send null as the id
    if (typeof id === 'string') {
      return stripeMethod({
        method: 'GET',
        path: 'accounts/{id}',
        urlParams: ['id'],
      }).apply(this, arguments);
    } else {
      if (id === null || id === undefined) {
        // Remove id as stripeMethod would complain of unexpected argument
        [].shift.apply(arguments);
      }
      return stripeMethod({
        method: 'GET',
        path: 'account',
      }).apply(this, arguments);
    }
  },

  /**
   * Accounts: External account methods
   */

  createExternalAccount: stripeMethod({
    method: 'POST',
    path: 'accounts/{accountId}/external_accounts',
    urlParams: ['accountId'],
  }),

  listExternalAccounts: stripeMethod({
    method: 'GET',
    path: 'accounts/{accountId}/external_accounts',
    urlParams: ['accountId'],
    methodType: 'list',
  }),

  retrieveExternalAccount: stripeMethod({
    method: 'GET',
    path: 'accounts/{accountId}/external_accounts/{externalAccountId}',
    urlParams: ['accountId', 'externalAccountId'],
  }),

  updateExternalAccount: stripeMethod({
    method: 'POST',
    path: 'accounts/{accountId}/external_accounts/{externalAccountId}',
    urlParams: ['accountId', 'externalAccountId'],
  }),

  deleteExternalAccount: stripeMethod({
    method: 'DELETE',
    path: 'accounts/{accountId}/external_accounts/{externalAccountId}',
    urlParams: ['accountId', 'externalAccountId'],
  }),

  /**
  * Accounts: LoginLink methods
  */

  createLoginLink: stripeMethod({
    method: 'POST',
    path: 'accounts/{accountId}/login_links',
    urlParams: ['accountId'],
  }),

  /**
   * Accounts: Person methods
   */

  createPerson: stripeMethod({
    method: 'POST',
    path: 'accounts/{accountId}/persons',
    urlParams: ['accountId'],
  }),

  listPersons: stripeMethod({
    method: 'GET',
    path: 'accounts/{accountId}/persons',
    urlParams: ['accountId'],
    methodType: 'list',
  }),

  retrievePerson: stripeMethod({
    method: 'GET',
    path: 'accounts/{accountId}/persons/{personId}',
    urlParams: ['accountId', 'personId'],
  }),

  updatePerson: stripeMethod({
    method: 'POST',
    path: 'accounts/{accountId}/persons/{personId}',
    urlParams: ['accountId', 'personId'],
  }),

  deletePerson: stripeMethod({
    method: 'DELETE',
    path: 'accounts/{accountId}/persons/{personId}',
    urlParams: ['accountId', 'personId'],
  }),
});


/***/ }),
/* 12 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(2);
var makeRequest = __webpack_require__(13);
var makeAutoPaginationMethods = __webpack_require__(28).makeAutoPaginationMethods;

/**
 * Create an API method from the declared spec.
 *
 * @param [spec.method='GET'] Request Method (POST, GET, DELETE, PUT)
 * @param [spec.path=''] Path to be appended to the API BASE_PATH, joined with
 *  the instance's path (e.g. 'charges' or 'customers')
 * @param [spec.urlParams=[]] Array of required arguments in the order that they
 *  must be passed by the consumer of the API. Subsequent optional arguments are
 *  optionally passed through a hash (Object) as the penultimate argument
 *  (preceding the also-optional callback argument
 * @param [spec.encode] Function for mutating input parameters to a method.
 *  Usefully for applying transforms to data on a per-method basis.
 * @param [spec.host] Hostname for the request.
 */
function stripeMethod(spec) {
  return function() {
    var self = this;
    var args = [].slice.call(arguments);

    var callback = typeof args[args.length - 1] == 'function' && args.pop();

    var requestPromise = utils.callbackifyPromiseWithTimeout(makeRequest(self, args, spec, {}), callback)

    if (spec.methodType === 'list') {
      var autoPaginationMethods = makeAutoPaginationMethods(self, args, spec, requestPromise);
      Object.assign(requestPromise, autoPaginationMethods);
    }

    return requestPromise;
  };
}

module.exports = stripeMethod;


/***/ }),
/* 13 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(2);
var OPTIONAL_REGEX = /^optional!/;

function getRequestOpts(self, requestArgs, spec, overrideData) {
  // Extract spec values with defaults.
  var commandPath = typeof spec.path == 'function' ? spec.path
    : utils.makeURLInterpolator(spec.path || '');
  var requestMethod = (spec.method || 'GET').toUpperCase();
  var urlParams = spec.urlParams || [];
  var encode = spec.encode || function(data) {return data;};
  var host = spec.host;

  // Don't mutate args externally.
  var args = [].slice.call(requestArgs);

  // Generate and validate url params.
  var urlData = self.createUrlData();
  for (var i = 0, l = urlParams.length; i < l; ++i) {
    var path;

    // Note that we shift the args array after every iteration so this just
    // grabs the "next" argument for use as a URL parameter.
    var arg = args[0];

    var param = urlParams[i];

    var isOptional = OPTIONAL_REGEX.test(param);
    param = param.replace(OPTIONAL_REGEX, '');

    if (param == 'id' && typeof arg !== 'string') {
      path = self.createResourcePathWithSymbols(spec.path);
      throw new Error(
        'Stripe: "id" must be a string, but got: ' + typeof arg +
        ' (on API request to `' + requestMethod + ' ' + path + '`)'
      );
    }

    if (!arg) {
      if (isOptional) {
        urlData[param] = '';
        continue;
      }

      path = self.createResourcePathWithSymbols(spec.path);
      throw new Error(
        'Stripe: Argument "' + urlParams[i] + '" required, but got: ' + arg +
        ' (on API request to `' + requestMethod + ' ' + path + '`)'
      );
    }

    urlData[param] = args.shift();
  }

  // Pull request data and options (headers, auth) from args.
  var dataFromArgs = utils.getDataFromArgs(args);
  var data = encode(Object.assign({}, dataFromArgs, overrideData));
  var options = utils.getOptionsFromArgs(args);

  // Validate that there are no more args.
  if (args.length) {
    path = self.createResourcePathWithSymbols(spec.path);
    throw new Error(
      'Stripe: Unknown arguments (' + args + '). Did you mean to pass an options ' +
      'object? See https://github.com/stripe/stripe-node/wiki/Passing-Options.' +
      ' (on API request to ' + requestMethod + ' `' + path + '`)'
    );
  }

  var requestPath = self.createFullPath(commandPath, urlData);
  var headers = Object.assign(options.headers, spec.headers);

  if (spec.validator) {
    spec.validator(data, {headers: headers});
  }

  return {
    requestMethod: requestMethod,
    requestPath: requestPath,
    data: data,
    auth: options.auth,
    headers: headers,
    host: host,
  };
}

function makeRequest(self, requestArgs, spec, overrideData) {
  return new Promise(function(resolve, reject) {
    try {
      var opts = getRequestOpts(self, requestArgs, spec, overrideData);
    } catch (err) {
      reject(err);
      return;
    }

    function requestCallback(err, response) {
      if (err) {
        reject(err);
      } else {
        resolve(
          spec.transformResponseData ?
            spec.transformResponseData(response) :
            response
        );
      }
    }

    self._request(opts.requestMethod, opts.host, opts.requestPath, opts.data, opts.auth, {headers: opts.headers}, requestCallback);
  });
}

module.exports = makeRequest;


/***/ }),
/* 14 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Buffer = __webpack_require__(4).Buffer;
var crypto = __webpack_require__(5);

var utils = __webpack_require__(2);
var Error = __webpack_require__(3);

var Webhook = {
  DEFAULT_TOLERANCE: 300, // 5 minutes

  constructEvent: function(payload, header, secret, tolerance) {
    this.signature.verifyHeader(payload, header, secret, tolerance || Webhook.DEFAULT_TOLERANCE);

    var jsonPayload = JSON.parse(payload);
    return jsonPayload;
  },
};

var signature = {
  EXPECTED_SCHEME: 'v1',

  _computeSignature: function(payload, secret) {
    return crypto.createHmac('sha256', secret)
      .update(payload, 'utf8')
      .digest('hex');
  },

  verifyHeader: function(payload, header, secret, tolerance) {
    payload = Buffer.isBuffer(payload) ? payload.toString('utf8') : payload;
    header = Buffer.isBuffer(header) ? header.toString('utf8') : header;

    var details = parseHeader(header, this.EXPECTED_SCHEME);

    if (!details || details.timestamp === -1) {
      throw new Error.StripeSignatureVerificationError({
        message: 'Unable to extract timestamp and signatures from header',
        detail: {
          header: header,
          payload: payload,
        },
      });
    }

    if (!details.signatures.length) {
      throw new Error.StripeSignatureVerificationError({
        message: 'No signatures found with expected scheme',
        detail: {
          header: header,
          payload: payload,
        },
      });
    }

    var expectedSignature = this._computeSignature(details.timestamp + '.' + payload, secret);

    var signatureFound = !!details.signatures
      .filter(utils.secureCompare.bind(utils, expectedSignature))
      .length;

    if (!signatureFound) {
      throw new Error.StripeSignatureVerificationError({
        message: 'No signatures found matching the expected signature for payload.' +
          ' Are you passing the raw request body you received from Stripe?' +
          ' https://github.com/stripe/stripe-node#webhook-signing',
        detail: {
          header: header,
          payload: payload,
        },
      });
    }

    var timestampAge = Math.floor(Date.now() / 1000) - details.timestamp;

    if (tolerance > 0 && timestampAge > tolerance) {
      throw new Error.StripeSignatureVerificationError({
        message: 'Timestamp outside the tolerance zone',
        detail: {
          header: header,
          payload: payload,
        },
      });
    }

    return true;
  },
};

function parseHeader(header, scheme) {
  if (typeof header !== 'string') {
    return null;
  }

  return header.split(',').reduce(function(accum, item) {
    var kv = item.split('=');

    if (kv[0] === 't') {
      accum.timestamp = kv[1];
    }

    if (kv[0] === scheme) {
      accum.signatures.push(kv[1]);
    }

    return accum;
  }, {
    timestamp: -1,
    signatures: [],
  });
}

Webhook.signature = signature;

module.exports = Webhook;


/***/ }),
/* 15 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Stripe.DEFAULT_HOST = 'api.stripe.com';
Stripe.DEFAULT_PORT = '443';
Stripe.DEFAULT_BASE_PATH = '/v1/';
Stripe.DEFAULT_API_VERSION = null;

// Use node's default timeout:
Stripe.DEFAULT_TIMEOUT = __webpack_require__(6).createServer().timeout;

Stripe.PACKAGE_VERSION = __webpack_require__(16).version;

Stripe.USER_AGENT = {
  bindings_version: Stripe.PACKAGE_VERSION,
  lang: 'node',
  lang_version: process.version,
  platform: process.platform,
  publisher: 'stripe',
  uname: null,
};

Stripe.USER_AGENT_SERIALIZED = null;

Stripe.MAX_NETWORK_RETRY_DELAY_SEC = 2;
Stripe.INITIAL_NETWORK_RETRY_DELAY_SEC = 0.5;

var APP_INFO_PROPERTIES = ['name', 'version', 'url', 'partner_id'];

var EventEmitter = __webpack_require__(7).EventEmitter;
var utils = __webpack_require__(2);

var resourceNamespace = __webpack_require__(22);

var resources = {
  // Support Accounts for consistency, Account for backwards compat
  Account: __webpack_require__(11),
  Accounts: __webpack_require__(11),
  AccountLinks: __webpack_require__(30),
  ApplePayDomains: __webpack_require__(31),
  ApplicationFees: __webpack_require__(32),
  Balance: __webpack_require__(33),
  BitcoinReceivers: __webpack_require__(34),
  Charges: __webpack_require__(35),
  CountrySpecs: __webpack_require__(36),
  Coupons: __webpack_require__(37),
  CreditNotes: __webpack_require__(38),
  Customers: __webpack_require__(39),
  Disputes: __webpack_require__(40),
  EphemeralKeys: __webpack_require__(41),
  Events: __webpack_require__(42),
  ExchangeRates: __webpack_require__(43),
  Files: __webpack_require__(44),
  FileLinks: __webpack_require__(46),
  InvoiceItems: __webpack_require__(47),
  Invoices: __webpack_require__(48),
  IssuerFraudRecords: __webpack_require__(49),
  LoginLinks: __webpack_require__(50),
  OAuth: __webpack_require__(51),
  OrderReturns: __webpack_require__(52),
  Orders: __webpack_require__(53),
  PaymentIntents: __webpack_require__(54),
  PaymentMethods: __webpack_require__(55),
  Payouts: __webpack_require__(56),
  Plans: __webpack_require__(57),
  Products: __webpack_require__(58),
  RecipientCards: __webpack_require__(59),
  Recipients: __webpack_require__(60),
  Refunds: __webpack_require__(61),
  Reviews: __webpack_require__(62),
  Skus: __webpack_require__(63),
  Sources: __webpack_require__(64),
  SubscriptionItems: __webpack_require__(65),
  SubscriptionSchedules: __webpack_require__(66),
  Subscriptions: __webpack_require__(67),
  TaxRates: __webpack_require__(68),
  ThreeDSecure: __webpack_require__(69),
  Tokens: __webpack_require__(70),
  Topups: __webpack_require__(71),
  Transfers: __webpack_require__(72),
  UsageRecords: __webpack_require__(73),
  UsageRecordSummaries: __webpack_require__(74),
  WebhookEndpoints: __webpack_require__(75),

  // The following rely on pre-filled IDs:
  ApplicationFeeRefunds: __webpack_require__(76),
  ChargeRefunds: __webpack_require__(77),
  CustomerCards: __webpack_require__(78),
  CustomerSubscriptions: __webpack_require__(79),
  Persons: __webpack_require__(80),
  SubscriptionScheduleRevisions: __webpack_require__(81),
  TaxIds: __webpack_require__(82),
  TransferReversals: __webpack_require__(83),

  // Namespaced resources
  Checkout: resourceNamespace('checkout', {
    Sessions: __webpack_require__(84),
  }),
  Issuing: resourceNamespace('issuing', {
    Authorizations: __webpack_require__(85),
    Cardholders: __webpack_require__(86),
    Cards: __webpack_require__(87),
    Disputes: __webpack_require__(88),
    Transactions: __webpack_require__(89),
  }),
  Radar: resourceNamespace('radar', {
    ValueLists: __webpack_require__(90),
    ValueListItems: __webpack_require__(91),
  }),
  Reporting: resourceNamespace('reporting', {
    ReportRuns: __webpack_require__(92),
    ReportTypes: __webpack_require__(93),
  }),
  Sigma: resourceNamespace('sigma', {
    ScheduledQueryRuns: __webpack_require__(94),
  }),
  Terminal: resourceNamespace('terminal', {
    ConnectionTokens: __webpack_require__(95),
    Locations: __webpack_require__(96),
    Readers: __webpack_require__(97),
  }),
};

// For backwards compatibility, `Files` is aliased to `FileUploads`
resources.FileUploads = resources.Files;

Stripe.StripeResource = __webpack_require__(1);
Stripe.resources = resources;

function Stripe(key, version) {
  if (!(this instanceof Stripe)) {
    return new Stripe(key, version);
  }

  Object.defineProperty(this, '_emitter', {
    value: new EventEmitter(),
    enumerable: false,
    configurable: false,
    writeable: false,
  });

  this.on = this._emitter.on.bind(this._emitter);
  this.off = this._emitter.removeListener.bind(this._emitter);

  this._api = {
    auth: null,
    host: Stripe.DEFAULT_HOST,
    port: Stripe.DEFAULT_PORT,
    basePath: Stripe.DEFAULT_BASE_PATH,
    version: Stripe.DEFAULT_API_VERSION,
    timeout: Stripe.DEFAULT_TIMEOUT,
    agent: null,
    dev: false,
    maxNetworkRetries: 0,
  };

  this._prepResources();
  this.setApiKey(key);
  this.setApiVersion(version);

  this.errors = __webpack_require__(3);
  this.webhooks = __webpack_require__(14);

  this._prevRequestMetrics = [];
  this.setTelemetryEnabled(false);
}

Stripe.errors = __webpack_require__(3);
Stripe.webhooks = __webpack_require__(14);

Stripe.prototype = {
  setHost: function(host, port, protocol) {
    this._setApiField('host', host);
    if (port) {
      this.setPort(port);
    }
    if (protocol) {
      this.setProtocol(protocol);
    }
  },

  setProtocol: function(protocol) {
    this._setApiField('protocol', protocol.toLowerCase());
  },

  setPort: function(port) {
    this._setApiField('port', port);
  },

  setApiVersion: function(version) {
    if (version) {
      this._setApiField('version', version);
    }
  },

  setApiKey: function(key) {
    if (key) {
      this._setApiField(
        'auth',
        'Bearer ' + key
      );
    }
  },

  setTimeout: function(timeout) {
    this._setApiField(
      'timeout',
      timeout == null ? Stripe.DEFAULT_TIMEOUT : timeout
    );
  },

  setAppInfo: function(info) {
    if (info && typeof info !== 'object') {
      throw new Error('AppInfo must be an object.');
    }

    if (info && !info.name) {
      throw new Error('AppInfo.name is required');
    }

    info = info || {};

    var appInfo = APP_INFO_PROPERTIES.reduce(function(accum, prop) {
      if (typeof info[prop] == 'string') {
        accum = accum || {};

        accum[prop] = info[prop];
      }

      return accum;
    }, undefined);

    // Kill the cached UA string because it may no longer be valid
    Stripe.USER_AGENT_SERIALIZED = undefined;

    this._appInfo = appInfo;
  },

  setHttpAgent: function(agent) {
    this._setApiField('agent', agent);
  },

  _setApiField: function(key, value) {
    this._api[key] = value;
  },

  getApiField: function(key) {
    return this._api[key];
  },

  setClientId: function(clientId) {
    this._clientId = clientId;
  },

  getClientId: function() {
    return this._clientId;
  },

  getConstant: function(c) {
    return Stripe[c];
  },

  getMaxNetworkRetries: function() {
    return this.getApiField('maxNetworkRetries');
  },

  setMaxNetworkRetries: function(maxNetworkRetries) {
    if ((maxNetworkRetries && typeof maxNetworkRetries !== 'number') || arguments.length < 1) {
      throw new Error('maxNetworkRetries must be a number.');
    }

    this._setApiField('maxNetworkRetries', maxNetworkRetries);
  },

  getMaxNetworkRetryDelay: function() {
    return this.getConstant('MAX_NETWORK_RETRY_DELAY_SEC');
  },

  getInitialNetworkRetryDelay: function() {
    return this.getConstant('INITIAL_NETWORK_RETRY_DELAY_SEC');
  },

  // Gets a JSON version of a User-Agent and uses a cached version for a slight
  // speed advantage.
  getClientUserAgent: function(cb) {
    if (Stripe.USER_AGENT_SERIALIZED) {
      return cb(Stripe.USER_AGENT_SERIALIZED);
    }
    this.getClientUserAgentSeeded(Stripe.USER_AGENT, function(cua) {
      Stripe.USER_AGENT_SERIALIZED = cua;
      cb(Stripe.USER_AGENT_SERIALIZED);
    })
  },

  // Gets a JSON version of a User-Agent by encoding a seeded object and
  // fetching a uname from the system.
  getClientUserAgentSeeded: function(seed, cb) {
    var self = this;

    utils.safeExec('uname -a', function(err, uname) {
      var userAgent = {};
      for (var field in seed) {
        userAgent[field] = encodeURIComponent(seed[field]);
      }

      // URI-encode in case there are unusual characters in the system's uname.
      userAgent.uname = encodeURIComponent(uname || 'UNKNOWN');

      if (self._appInfo) {
        userAgent.application = self._appInfo;
      }

      cb(JSON.stringify(userAgent))
    });
  },

  getAppInfoAsString: function() {
    if (!this._appInfo) {
      return '';
    }

    var formatted = this._appInfo.name;

    if (this._appInfo.version) {
      formatted += '/' + this._appInfo.version;
    }

    if (this._appInfo.url) {
      formatted += ' (' + this._appInfo.url + ')';
    }

    return formatted;
  },

  setTelemetryEnabled: function(enableTelemetry) {
    this._enableTelemetry = enableTelemetry;
  },

  getTelemetryEnabled: function() {
    return this._enableTelemetry;
  },

  _prepResources: function() {
    for (var name in resources) {
      this[utils.pascalToCamelCase(name)] = new resources[name](this);
    }
  },
};

module.exports = Stripe;
// expose constructor as a named property to enable mocking with Sinon.JS
module.exports.Stripe = Stripe;


/***/ }),
/* 16 */
/***/ (function(module, exports) {

module.exports = {"_from":"stripe","_id":"stripe@6.31.2","_inBundle":false,"_integrity":"sha512-QQtRRm3YxhRuNAoGikLy8DM4k0/wYLIEmPUIpyweCWcW1R0H6gkzlNjAKf9+Ig29K8kUn/BjUks1WJ4IBzpgTg==","_location":"/stripe","_phantomChildren":{},"_requested":{"type":"tag","registry":true,"raw":"stripe","name":"stripe","escapedName":"stripe","rawSpec":"","saveSpec":null,"fetchSpec":"latest"},"_requiredBy":["#USER","/"],"_resolved":"https://registry.npmjs.org/stripe/-/stripe-6.31.2.tgz","_shasum":"2250344e021553d494c6867664fdab06f91c224b","_spec":"stripe","_where":"/Users/fumiya/Library/Mobile Documents/com~apple~CloudDocs/project/designcode/react-for-designer/my-app","author":{"name":"Stripe","email":"support@stripe.com","url":"https://stripe.com/"},"bugs":{"url":"https://github.com/stripe/stripe-node/issues"},"bugs:":"https://github.com/stripe/stripe-node/issues","bundleDependencies":false,"contributors":[{"name":"Ask Bjørn Hansen","email":"ask@develooper.com","url":"http://www.askask.com/"},{"name":"Michelle Bu","email":"michelle@stripe.com"},{"name":"Alex Sexton","email":"alex@stripe.com"},{"name":"James Padolsey"}],"dependencies":{"lodash.isplainobject":"^4.0.6","qs":"^6.6.0","safe-buffer":"^5.1.1","uuid":"^3.3.2"},"deprecated":false,"description":"Stripe API wrapper","devDependencies":{"chai":"~4.1.2","chai-as-promised":"~7.1.1","coveralls":"^3.0.0","eslint":"^4.19.1","eslint-plugin-chai-friendly":"^0.4.0","mocha":"~5.0.5","nock":"^9.0.0","nyc":"^11.3.0"},"engines":{"node":">=4"},"homepage":"https://github.com/stripe/stripe-node","keywords":["stripe","payment processing","credit cards","api"],"license":"MIT","main":"lib/stripe.js","name":"stripe","repository":{"type":"git","url":"git://github.com/stripe/stripe-node.git"},"scripts":{"clean":"rm -rf ./.nyc_output ./node_modules/.cache ./coverage","coveralls":"cat coverage/lcov.info | ./node_modules/coveralls/bin/coveralls.js","lint":"eslint .","mocha":"nyc mocha","report":"nyc -r text -r lcov report","test":"npm run lint && npm run mocha"},"version":"6.31.2"}

/***/ }),
/* 17 */
/***/ (function(module, exports) {

module.exports = require("buffer");

/***/ }),
/* 18 */
/***/ (function(module, exports) {

module.exports = require("child_process");

/***/ }),
/* 19 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var stringify = __webpack_require__(20);
var parse = __webpack_require__(21);
var formats = __webpack_require__(9);

module.exports = {
    formats: formats,
    parse: parse,
    stringify: stringify
};


/***/ }),
/* 20 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(8);
var formats = __webpack_require__(9);
var has = Object.prototype.hasOwnProperty;

var arrayPrefixGenerators = {
    brackets: function brackets(prefix) { // eslint-disable-line func-name-matching
        return prefix + '[]';
    },
    comma: 'comma',
    indices: function indices(prefix, key) { // eslint-disable-line func-name-matching
        return prefix + '[' + key + ']';
    },
    repeat: function repeat(prefix) { // eslint-disable-line func-name-matching
        return prefix;
    }
};

var isArray = Array.isArray;
var push = Array.prototype.push;
var pushToArray = function (arr, valueOrArray) {
    push.apply(arr, isArray(valueOrArray) ? valueOrArray : [valueOrArray]);
};

var toISO = Date.prototype.toISOString;

var defaults = {
    addQueryPrefix: false,
    allowDots: false,
    charset: 'utf-8',
    charsetSentinel: false,
    delimiter: '&',
    encode: true,
    encoder: utils.encode,
    encodeValuesOnly: false,
    formatter: formats.formatters[formats['default']],
    // deprecated
    indices: false,
    serializeDate: function serializeDate(date) { // eslint-disable-line func-name-matching
        return toISO.call(date);
    },
    skipNulls: false,
    strictNullHandling: false
};

var stringify = function stringify( // eslint-disable-line func-name-matching
    object,
    prefix,
    generateArrayPrefix,
    strictNullHandling,
    skipNulls,
    encoder,
    filter,
    sort,
    allowDots,
    serializeDate,
    formatter,
    encodeValuesOnly,
    charset
) {
    var obj = object;
    if (typeof filter === 'function') {
        obj = filter(prefix, obj);
    } else if (obj instanceof Date) {
        obj = serializeDate(obj);
    } else if (generateArrayPrefix === 'comma' && isArray(obj)) {
        obj = obj.join(',');
    }

    if (obj === null) {
        if (strictNullHandling) {
            return encoder && !encodeValuesOnly ? encoder(prefix, defaults.encoder, charset) : prefix;
        }

        obj = '';
    }

    if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean' || utils.isBuffer(obj)) {
        if (encoder) {
            var keyValue = encodeValuesOnly ? prefix : encoder(prefix, defaults.encoder, charset);
            return [formatter(keyValue) + '=' + formatter(encoder(obj, defaults.encoder, charset))];
        }
        return [formatter(prefix) + '=' + formatter(String(obj))];
    }

    var values = [];

    if (typeof obj === 'undefined') {
        return values;
    }

    var objKeys;
    if (isArray(filter)) {
        objKeys = filter;
    } else {
        var keys = Object.keys(obj);
        objKeys = sort ? keys.sort(sort) : keys;
    }

    for (var i = 0; i < objKeys.length; ++i) {
        var key = objKeys[i];

        if (skipNulls && obj[key] === null) {
            continue;
        }

        if (isArray(obj)) {
            pushToArray(values, stringify(
                obj[key],
                typeof generateArrayPrefix === 'function' ? generateArrayPrefix(prefix, key) : prefix,
                generateArrayPrefix,
                strictNullHandling,
                skipNulls,
                encoder,
                filter,
                sort,
                allowDots,
                serializeDate,
                formatter,
                encodeValuesOnly,
                charset
            ));
        } else {
            pushToArray(values, stringify(
                obj[key],
                prefix + (allowDots ? '.' + key : '[' + key + ']'),
                generateArrayPrefix,
                strictNullHandling,
                skipNulls,
                encoder,
                filter,
                sort,
                allowDots,
                serializeDate,
                formatter,
                encodeValuesOnly,
                charset
            ));
        }
    }

    return values;
};

var normalizeStringifyOptions = function normalizeStringifyOptions(opts) {
    if (!opts) {
        return defaults;
    }

    if (opts.encoder !== null && opts.encoder !== undefined && typeof opts.encoder !== 'function') {
        throw new TypeError('Encoder has to be a function.');
    }

    var charset = opts.charset || defaults.charset;
    if (typeof opts.charset !== 'undefined' && opts.charset !== 'utf-8' && opts.charset !== 'iso-8859-1') {
        throw new TypeError('The charset option must be either utf-8, iso-8859-1, or undefined');
    }

    var format = formats['default'];
    if (typeof opts.format !== 'undefined') {
        if (!has.call(formats.formatters, opts.format)) {
            throw new TypeError('Unknown format option provided.');
        }
        format = opts.format;
    }
    var formatter = formats.formatters[format];

    var filter = defaults.filter;
    if (typeof opts.filter === 'function' || isArray(opts.filter)) {
        filter = opts.filter;
    }

    return {
        addQueryPrefix: typeof opts.addQueryPrefix === 'boolean' ? opts.addQueryPrefix : defaults.addQueryPrefix,
        allowDots: typeof opts.allowDots === 'undefined' ? defaults.allowDots : !!opts.allowDots,
        charset: charset,
        charsetSentinel: typeof opts.charsetSentinel === 'boolean' ? opts.charsetSentinel : defaults.charsetSentinel,
        delimiter: typeof opts.delimiter === 'undefined' ? defaults.delimiter : opts.delimiter,
        encode: typeof opts.encode === 'boolean' ? opts.encode : defaults.encode,
        encoder: typeof opts.encoder === 'function' ? opts.encoder : defaults.encoder,
        encodeValuesOnly: typeof opts.encodeValuesOnly === 'boolean' ? opts.encodeValuesOnly : defaults.encodeValuesOnly,
        filter: filter,
        formatter: formatter,
        serializeDate: typeof opts.serializeDate === 'function' ? opts.serializeDate : defaults.serializeDate,
        skipNulls: typeof opts.skipNulls === 'boolean' ? opts.skipNulls : defaults.skipNulls,
        sort: typeof opts.sort === 'function' ? opts.sort : null,
        strictNullHandling: typeof opts.strictNullHandling === 'boolean' ? opts.strictNullHandling : defaults.strictNullHandling
    };
};

module.exports = function (object, opts) {
    var obj = object;
    var options = normalizeStringifyOptions(opts);

    var objKeys;
    var filter;

    if (typeof options.filter === 'function') {
        filter = options.filter;
        obj = filter('', obj);
    } else if (isArray(options.filter)) {
        filter = options.filter;
        objKeys = filter;
    }

    var keys = [];

    if (typeof obj !== 'object' || obj === null) {
        return '';
    }

    var arrayFormat;
    if (opts && opts.arrayFormat in arrayPrefixGenerators) {
        arrayFormat = opts.arrayFormat;
    } else if (opts && 'indices' in opts) {
        arrayFormat = opts.indices ? 'indices' : 'repeat';
    } else {
        arrayFormat = 'indices';
    }

    var generateArrayPrefix = arrayPrefixGenerators[arrayFormat];

    if (!objKeys) {
        objKeys = Object.keys(obj);
    }

    if (options.sort) {
        objKeys.sort(options.sort);
    }

    for (var i = 0; i < objKeys.length; ++i) {
        var key = objKeys[i];

        if (options.skipNulls && obj[key] === null) {
            continue;
        }
        pushToArray(keys, stringify(
            obj[key],
            key,
            generateArrayPrefix,
            options.strictNullHandling,
            options.skipNulls,
            options.encode ? options.encoder : null,
            options.filter,
            options.sort,
            options.allowDots,
            options.serializeDate,
            options.formatter,
            options.encodeValuesOnly,
            options.charset
        ));
    }

    var joined = keys.join(options.delimiter);
    var prefix = options.addQueryPrefix === true ? '?' : '';

    if (options.charsetSentinel) {
        if (options.charset === 'iso-8859-1') {
            // encodeURIComponent('&#10003;'), the "numeric entity" representation of a checkmark
            prefix += 'utf8=%26%2310003%3B&';
        } else {
            // encodeURIComponent('✓')
            prefix += 'utf8=%E2%9C%93&';
        }
    }

    return joined.length > 0 ? prefix + joined : '';
};


/***/ }),
/* 21 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(8);

var has = Object.prototype.hasOwnProperty;

var defaults = {
    allowDots: false,
    allowPrototypes: false,
    arrayLimit: 20,
    charset: 'utf-8',
    charsetSentinel: false,
    comma: false,
    decoder: utils.decode,
    delimiter: '&',
    depth: 5,
    ignoreQueryPrefix: false,
    interpretNumericEntities: false,
    parameterLimit: 1000,
    parseArrays: true,
    plainObjects: false,
    strictNullHandling: false
};

var interpretNumericEntities = function (str) {
    return str.replace(/&#(\d+);/g, function ($0, numberStr) {
        return String.fromCharCode(parseInt(numberStr, 10));
    });
};

// This is what browsers will submit when the ✓ character occurs in an
// application/x-www-form-urlencoded body and the encoding of the page containing
// the form is iso-8859-1, or when the submitted form has an accept-charset
// attribute of iso-8859-1. Presumably also with other charsets that do not contain
// the ✓ character, such as us-ascii.
var isoSentinel = 'utf8=%26%2310003%3B'; // encodeURIComponent('&#10003;')

// These are the percent-encoded utf-8 octets representing a checkmark, indicating that the request actually is utf-8 encoded.
var charsetSentinel = 'utf8=%E2%9C%93'; // encodeURIComponent('✓')

var parseValues = function parseQueryStringValues(str, options) {
    var obj = {};
    var cleanStr = options.ignoreQueryPrefix ? str.replace(/^\?/, '') : str;
    var limit = options.parameterLimit === Infinity ? undefined : options.parameterLimit;
    var parts = cleanStr.split(options.delimiter, limit);
    var skipIndex = -1; // Keep track of where the utf8 sentinel was found
    var i;

    var charset = options.charset;
    if (options.charsetSentinel) {
        for (i = 0; i < parts.length; ++i) {
            if (parts[i].indexOf('utf8=') === 0) {
                if (parts[i] === charsetSentinel) {
                    charset = 'utf-8';
                } else if (parts[i] === isoSentinel) {
                    charset = 'iso-8859-1';
                }
                skipIndex = i;
                i = parts.length; // The eslint settings do not allow break;
            }
        }
    }

    for (i = 0; i < parts.length; ++i) {
        if (i === skipIndex) {
            continue;
        }
        var part = parts[i];

        var bracketEqualsPos = part.indexOf(']=');
        var pos = bracketEqualsPos === -1 ? part.indexOf('=') : bracketEqualsPos + 1;

        var key, val;
        if (pos === -1) {
            key = options.decoder(part, defaults.decoder, charset);
            val = options.strictNullHandling ? null : '';
        } else {
            key = options.decoder(part.slice(0, pos), defaults.decoder, charset);
            val = options.decoder(part.slice(pos + 1), defaults.decoder, charset);
        }

        if (val && options.interpretNumericEntities && charset === 'iso-8859-1') {
            val = interpretNumericEntities(val);
        }

        if (val && options.comma && val.indexOf(',') > -1) {
            val = val.split(',');
        }

        if (has.call(obj, key)) {
            obj[key] = utils.combine(obj[key], val);
        } else {
            obj[key] = val;
        }
    }

    return obj;
};

var parseObject = function (chain, val, options) {
    var leaf = val;

    for (var i = chain.length - 1; i >= 0; --i) {
        var obj;
        var root = chain[i];

        if (root === '[]' && options.parseArrays) {
            obj = [].concat(leaf);
        } else {
            obj = options.plainObjects ? Object.create(null) : {};
            var cleanRoot = root.charAt(0) === '[' && root.charAt(root.length - 1) === ']' ? root.slice(1, -1) : root;
            var index = parseInt(cleanRoot, 10);
            if (!options.parseArrays && cleanRoot === '') {
                obj = { 0: leaf };
            } else if (
                !isNaN(index)
                && root !== cleanRoot
                && String(index) === cleanRoot
                && index >= 0
                && (options.parseArrays && index <= options.arrayLimit)
            ) {
                obj = [];
                obj[index] = leaf;
            } else {
                obj[cleanRoot] = leaf;
            }
        }

        leaf = obj;
    }

    return leaf;
};

var parseKeys = function parseQueryStringKeys(givenKey, val, options) {
    if (!givenKey) {
        return;
    }

    // Transform dot notation to bracket notation
    var key = options.allowDots ? givenKey.replace(/\.([^.[]+)/g, '[$1]') : givenKey;

    // The regex chunks

    var brackets = /(\[[^[\]]*])/;
    var child = /(\[[^[\]]*])/g;

    // Get the parent

    var segment = brackets.exec(key);
    var parent = segment ? key.slice(0, segment.index) : key;

    // Stash the parent if it exists

    var keys = [];
    if (parent) {
        // If we aren't using plain objects, optionally prefix keys that would overwrite object prototype properties
        if (!options.plainObjects && has.call(Object.prototype, parent)) {
            if (!options.allowPrototypes) {
                return;
            }
        }

        keys.push(parent);
    }

    // Loop through children appending to the array until we hit depth

    var i = 0;
    while ((segment = child.exec(key)) !== null && i < options.depth) {
        i += 1;
        if (!options.plainObjects && has.call(Object.prototype, segment[1].slice(1, -1))) {
            if (!options.allowPrototypes) {
                return;
            }
        }
        keys.push(segment[1]);
    }

    // If there's a remainder, just add whatever is left

    if (segment) {
        keys.push('[' + key.slice(segment.index) + ']');
    }

    return parseObject(keys, val, options);
};

var normalizeParseOptions = function normalizeParseOptions(opts) {
    if (!opts) {
        return defaults;
    }

    if (opts.decoder !== null && opts.decoder !== undefined && typeof opts.decoder !== 'function') {
        throw new TypeError('Decoder has to be a function.');
    }

    if (typeof opts.charset !== 'undefined' && opts.charset !== 'utf-8' && opts.charset !== 'iso-8859-1') {
        throw new Error('The charset option must be either utf-8, iso-8859-1, or undefined');
    }
    var charset = typeof opts.charset === 'undefined' ? defaults.charset : opts.charset;

    return {
        allowDots: typeof opts.allowDots === 'undefined' ? defaults.allowDots : !!opts.allowDots,
        allowPrototypes: typeof opts.allowPrototypes === 'boolean' ? opts.allowPrototypes : defaults.allowPrototypes,
        arrayLimit: typeof opts.arrayLimit === 'number' ? opts.arrayLimit : defaults.arrayLimit,
        charset: charset,
        charsetSentinel: typeof opts.charsetSentinel === 'boolean' ? opts.charsetSentinel : defaults.charsetSentinel,
        comma: typeof opts.comma === 'boolean' ? opts.comma : defaults.comma,
        decoder: typeof opts.decoder === 'function' ? opts.decoder : defaults.decoder,
        delimiter: typeof opts.delimiter === 'string' || utils.isRegExp(opts.delimiter) ? opts.delimiter : defaults.delimiter,
        depth: typeof opts.depth === 'number' ? opts.depth : defaults.depth,
        ignoreQueryPrefix: opts.ignoreQueryPrefix === true,
        interpretNumericEntities: typeof opts.interpretNumericEntities === 'boolean' ? opts.interpretNumericEntities : defaults.interpretNumericEntities,
        parameterLimit: typeof opts.parameterLimit === 'number' ? opts.parameterLimit : defaults.parameterLimit,
        parseArrays: opts.parseArrays !== false,
        plainObjects: typeof opts.plainObjects === 'boolean' ? opts.plainObjects : defaults.plainObjects,
        strictNullHandling: typeof opts.strictNullHandling === 'boolean' ? opts.strictNullHandling : defaults.strictNullHandling
    };
};

module.exports = function (str, opts) {
    var options = normalizeParseOptions(opts);

    if (str === '' || str === null || typeof str === 'undefined') {
        return options.plainObjects ? Object.create(null) : {};
    }

    var tempObj = typeof str === 'string' ? parseValues(str, options) : str;
    var obj = options.plainObjects ? Object.create(null) : {};

    // Iterate over the keys and setup the new object

    var keys = Object.keys(tempObj);
    for (var i = 0; i < keys.length; ++i) {
        var key = keys[i];
        var newObj = parseKeys(key, tempObj[key], options);
        obj = utils.merge(obj, newObj, options);
    }

    return utils.compact(obj);
};


/***/ }),
/* 22 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


// ResourceNamespace allows you to create nested resources, i.e. `stripe.issuing.cards`.
// It also works recursively, so you could do i.e. `stripe.billing.invoicing.pay`.

function ResourceNamespace(stripe, resources) {
  for (var name in resources) {
    var camelCaseName = name[0].toLowerCase() + name.substring(1);

    var resource = new resources[name](stripe);

    this[camelCaseName] = resource;
  }
}

module.exports = function(namespace, resources) {
  return function (stripe) {
    return new ResourceNamespace(stripe, resources);
  };
};

module.exports.ResourceNamespace = ResourceNamespace;


/***/ }),
/* 23 */
/***/ (function(module, exports) {

module.exports = require("https");

/***/ }),
/* 24 */
/***/ (function(module, exports) {

module.exports = require("path");

/***/ }),
/* 25 */
/***/ (function(module, exports, __webpack_require__) {

var rng = __webpack_require__(26);
var bytesToUuid = __webpack_require__(27);

function v4(options, buf, offset) {
  var i = buf && offset || 0;

  if (typeof(options) == 'string') {
    buf = options === 'binary' ? new Array(16) : null;
    options = null;
  }
  options = options || {};

  var rnds = options.random || (options.rng || rng)();

  // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
  rnds[6] = (rnds[6] & 0x0f) | 0x40;
  rnds[8] = (rnds[8] & 0x3f) | 0x80;

  // Copy bytes to buffer, if provided
  if (buf) {
    for (var ii = 0; ii < 16; ++ii) {
      buf[i + ii] = rnds[ii];
    }
  }

  return buf || bytesToUuid(rnds);
}

module.exports = v4;


/***/ }),
/* 26 */
/***/ (function(module, exports, __webpack_require__) {

// Unique ID creation requires a high quality random # generator.  In node.js
// this is pretty straight-forward - we use the crypto API.

var crypto = __webpack_require__(5);

module.exports = function nodeRNG() {
  return crypto.randomBytes(16);
};


/***/ }),
/* 27 */
/***/ (function(module, exports) {

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];
for (var i = 0; i < 256; ++i) {
  byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex;
  // join used to fix memory issue caused by concatenation: https://bugs.chromium.org/p/v8/issues/detail?id=3175#c4
  return ([bth[buf[i++]], bth[buf[i++]], 
	bth[buf[i++]], bth[buf[i++]], '-',
	bth[buf[i++]], bth[buf[i++]], '-',
	bth[buf[i++]], bth[buf[i++]], '-',
	bth[buf[i++]], bth[buf[i++]], '-',
	bth[buf[i++]], bth[buf[i++]],
	bth[buf[i++]], bth[buf[i++]],
	bth[buf[i++]], bth[buf[i++]]]).join('');
}

module.exports = bytesToUuid;


/***/ }),
/* 28 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var makeRequest = __webpack_require__(13);
var utils = __webpack_require__(2);

function makeAutoPaginationMethods(self, requestArgs, spec, firstPagePromise) {
  var promiseCache = {currentPromise: null};
  var listPromise = firstPagePromise;
  var i = 0;

  function iterate(listResult) {
    if (!(listResult && listResult.data && typeof listResult.data.length === 'number')) {
      throw Error('Unexpected: Stripe API response does not have a well-formed `data` array.');
    }

    if (i < listResult.data.length) {
      var value = listResult.data[i];
      i += 1;
      return {value: value, done: false};
    } else if (listResult.has_more) {
      // Reset counter, request next page, and recurse.
      i = 0;
      var lastId = getLastId(listResult);
      listPromise = makeRequest(self, requestArgs, spec, {starting_after: lastId});
      return listPromise.then(iterate);
    }
    return {value: undefined, done: true};
  }

  function asyncIteratorNext() {
    return memoizedPromise(promiseCache, function(resolve, reject) {
      return listPromise
        .then(iterate)
        .then(resolve)
        .catch(reject);
    });
  }

  var autoPagingEach = makeAutoPagingEach(asyncIteratorNext);
  var autoPagingToArray = makeAutoPagingToArray(autoPagingEach);

  var autoPaginationMethods = {
    autoPagingEach: autoPagingEach,
    autoPagingToArray: autoPagingToArray,

    // Async iterator functions:
    next: asyncIteratorNext,
    return: function() {
      // This is required for `break`.
      return {};
    },
    [getAsyncIteratorSymbol()]: function() {
      return autoPaginationMethods;
    }
  };
  return autoPaginationMethods;
}

module.exports.makeAutoPaginationMethods = makeAutoPaginationMethods;

/**
 * ----------------
 * Private Helpers:
 * ----------------
 */

function getAsyncIteratorSymbol() {
  if (typeof Symbol !== 'undefined' && Symbol.asyncIterator) {
    return Symbol.asyncIterator;
  }
  // Follow the convention from libraries like iterall: https://github.com/leebyron/iterall#asynciterator-1
  return '@@asyncIterator';
}

function getDoneCallback(args) {
  if (args.length < 2) {
    return undefined;
  }
  var onDone = args[1];
  if (typeof onDone !== 'function') {
    throw Error('The second argument to autoPagingEach, if present, must be a callback function; receieved ' + typeof onDone);
  }
  return onDone;
}

/**
 * We allow four forms of the `onItem` callback (the middle two being equivalent),
 *
 *   1. `.autoPagingEach((item) => { doSomething(item); return false; });`
 *   2. `.autoPagingEach(async (item) => { await doSomething(item); return false; });`
 *   3. `.autoPagingEach((item) => doSomething(item).then(() => false));`
 *   4. `.autoPagingEach((item, next) => { doSomething(item); next(false); });`
 *
 * In addition to standard validation, this helper
 * coalesces the former forms into the latter form.
 */
function getItemCallback(args) {
  if (args.length === 0) {
    return undefined;
  }
  var onItem = args[0];
  if (typeof onItem !== 'function') {
    throw Error('The first argument to autoPagingEach, if present, must be a callback function; receieved ' + typeof onItem);
  }

  // 4. `.autoPagingEach((item, next) => { doSomething(item); next(false); });`
  if (onItem.length === 2) {
    return onItem;
  }

  if (onItem.length > 2) {
    throw Error('The `onItem` callback function passed to autoPagingEach must accept at most two arguments; got ' + onItem);
  }

  // This magically handles all three of these usecases (the latter two being functionally identical):
  // 1. `.autoPagingEach((item) => { doSomething(item); return false; });`
  // 2. `.autoPagingEach(async (item) => { await doSomething(item); return false; });`
  // 3. `.autoPagingEach((item) => doSomething(item).then(() => false));`
  return function _onItem(item, next) {
    var shouldContinue = onItem(item);
    next(shouldContinue);
  };
}

function getLastId(listResult) {
  var lastIdx = listResult.data.length - 1;
  var lastItem = listResult.data[lastIdx];
  var lastId = lastItem && lastItem.id;
  if (!lastId) {
    throw Error('Unexpected: No `id` found on the last item while auto-paging a list.');
  }
  return lastId;
}

/**
 * If a user calls `.next()` multiple times in parallel,
 * return the same result until something has resolved
 * to prevent page-turning race conditions.
 */
function memoizedPromise(promiseCache, cb) {
  if (promiseCache.currentPromise) {
    return promiseCache.currentPromise;
  }
  promiseCache.currentPromise = new Promise(cb).then(function(ret) {
    promiseCache.currentPromise = undefined;
    return ret;
  });
  return promiseCache.currentPromise;
}

function makeAutoPagingEach(asyncIteratorNext) {
  return function autoPagingEach(/* onItem?, onDone? */) {
    var args = [].slice.call(arguments);
    var onItem = getItemCallback(args);
    var onDone = getDoneCallback(args);
    if (args.length > 2) {
      throw Error('autoPagingEach takes up to two arguments; received:', args);
    }

    var autoPagePromise = wrapAsyncIteratorWithCallback(asyncIteratorNext, onItem);
    return utils.callbackifyPromiseWithTimeout(autoPagePromise, onDone);
  }
}

function makeAutoPagingToArray(autoPagingEach) {
  return function autoPagingToArray(opts, onDone) {
    var limit = opts && opts.limit;
    if (!limit) {
      throw Error('You must pass a `limit` option to autoPagingToArray, eg; `autoPagingToArray({limit: 1000});`.');
    }
    if (limit > 10000) {
      throw Error('You cannot specify a limit of more than 10,000 items to fetch in `autoPagingToArray`; use `autoPagingEach` to iterate through longer lists.');
    }
    var promise = new Promise(function(resolve, reject) {
      var items = [];
      autoPagingEach(function(item) {
        items.push(item);
        if (items.length >= limit) {
          return false;
        }
      }).then(function() {
        resolve(items);
      }).catch(reject);
    });
    return utils.callbackifyPromiseWithTimeout(promise, onDone);
  }
}

function wrapAsyncIteratorWithCallback(asyncIteratorNext, onItem) {
  return new Promise(function(resolve, reject) {
    function handleIteration(iterResult) {
      if (iterResult.done) {
        resolve();
        return;
      }

      var item = iterResult.value;
      return new Promise(function(next) {
        // Bit confusing, perhaps; we pass a `resolve` fn
        // to the user, so they can decide when and if to continue.
        // They can return false, or a promise which resolves to false, to break.
        onItem(item, next);
      }).then(function(shouldContinue) {
        if (shouldContinue === false) {
          return handleIteration({done: true});
        } else {
          return asyncIteratorNext().then(handleIteration);
        }
      });
    }

    asyncIteratorNext().then(handleIteration).catch(reject);
  });
}


/***/ }),
/* 29 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var isPlainObject = __webpack_require__(10);
var stripeMethod = __webpack_require__(12);
var utils = __webpack_require__(2);

module.exports = {

  create: stripeMethod({
    method: 'POST',
  }),

  list: stripeMethod({
    method: 'GET',
    methodType: 'list',
  }),

  retrieve: stripeMethod({
    method: 'GET',
    path: '/{id}',
    urlParams: ['id'],
  }),

  update: stripeMethod({
    method: 'POST',
    path: '{id}',
    urlParams: ['id'],
  }),

  // Avoid 'delete' keyword in JS
  del: stripeMethod({
    method: 'DELETE',
    path: '{id}',
    urlParams: ['id'],
  }),

  setMetadata: function(id, key, value, auth, cb) {
    var self = this;
    var data = key;
    var isObject = isPlainObject(key);
    // We assume null for an empty object
    var isNull = data === null || (isObject && !Object.keys(data).length);

    // Allow optional passing of auth & cb:
    if ((isNull || isObject) && typeof value == 'string') {
      auth = value;
    } else if (typeof auth != 'string') {
      if (!cb && typeof auth == 'function') {
        cb = auth;
      }
      auth = null;
    }

    var urlData = this.createUrlData();
    var path = this.createFullPath('/' + id, urlData);

    return utils.callbackifyPromiseWithTimeout(new Promise((function(resolve, reject) {
      if (isNull) {
        // Reset metadata:
        sendMetadata(null, auth);
      } else if (!isObject) {
        // Set individual metadata property:
        var metadata = {};
        metadata[key] = value;
        sendMetadata(metadata, auth);
      } else {
        // Set entire metadata object after resetting it:
        this._request('POST', null, path, {
          metadata: null,
        }, auth, {}, function(err, response) {
          if (err) {
            return reject(err);
          }
          sendMetadata(data, auth);
        });
      }

      function sendMetadata(metadata, auth) {
        self._request('POST', null, path, {
          metadata: metadata,
        }, auth, {}, function(err, response) {
          if (err) {
            reject(err);
          } else {
            resolve(response.metadata);
          }
        });
      }
    }).bind(this)), cb);
  },

  getMetadata: function(id, auth, cb) {
    if (!cb && typeof auth == 'function') {
      cb = auth;
      auth = null;
    }

    var urlData = this.createUrlData();
    var path = this.createFullPath('/' + id, urlData);

    return utils.callbackifyPromiseWithTimeout(new Promise((function(resolve, reject) {
      this._request('GET', null, path, {}, auth, {}, function(err, response) {
        if (err) {
          reject(err);
        } else {
          resolve(response.metadata);
        }
      });
    }).bind(this)), cb);
  },

};


/***/ }),
/* 30 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'account_links',
  includeBasic: ['create'],
});



/***/ }),
/* 31 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'apple_pay/domains',
  includeBasic: ['create', 'list', 'retrieve', 'del'],
});


/***/ }),
/* 32 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'application_fees',

  includeBasic: [
    'list', 'retrieve',
  ],

  refund: stripeMethod({
    method: 'POST',
    path: '/{id}/refund',
    urlParams: ['id'],
  }),

  createRefund: stripeMethod({
    method: 'POST',
    path: '/{feeId}/refunds',
    urlParams: ['feeId'],
  }),

  listRefunds: stripeMethod({
    method: 'GET',
    path: '/{feeId}/refunds',
    urlParams: ['feeId'],
    methodType: 'list',
  }),

  retrieveRefund: stripeMethod({
    method: 'GET',
    path: '/{feeId}/refunds/{refundId}',
    urlParams: ['feeId', 'refundId'],
  }),

  updateRefund: stripeMethod({
    method: 'POST',
    path: '/{feeId}/refunds/{refundId}',
    urlParams: ['feeId', 'refundId'],
  }),
});


/***/ }),
/* 33 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'balance',

  retrieve: stripeMethod({
    method: 'GET',
  }),

  listTransactions: stripeMethod({
    method: 'GET',
    path: 'history',
    methodType: 'list',
  }),

  retrieveTransaction: stripeMethod({
    method: 'GET',
    path: 'history/{transactionId}',
    urlParams: ['transactionId'],
  }),

});


/***/ }),
/* 34 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'bitcoin/receivers',

  includeBasic: [
    'list', 'retrieve', 'getMetadata',
  ],

  listTransactions: stripeMethod({
    method: 'GET',
    path: '/{receiverId}/transactions',
    urlParams: ['receiverId'],
    methodType: 'list',
  }),
});


/***/ }),
/* 35 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'charges',

  includeBasic: [
    'create', 'list', 'retrieve', 'update',
    'setMetadata', 'getMetadata',
  ],

  capture: stripeMethod({
    method: 'POST',
    path: '/{id}/capture',
    urlParams: ['id'],
  }),

  refund: stripeMethod({
    method: 'POST',
    path: '/{id}/refund',
    urlParams: ['id'],
  }),

  updateDispute: stripeMethod({
    method: 'POST',
    path: '/{id}/dispute',
    urlParams: ['id'],
  }),

  closeDispute: stripeMethod({
    method: 'POST',
    path: '/{id}/dispute/close',
    urlParams: ['id'],
  }),

  /**
   * Charge: Refund methods
   * (Deprecated)
   */
  createRefund: stripeMethod({
    method: 'POST',
    path: '/{chargeId}/refunds',
    urlParams: ['chargeId'],
  }),

  listRefunds: stripeMethod({
    method: 'GET',
    path: '/{chargeId}/refunds',
    urlParams: ['chargeId'],
    methodType: 'list',
  }),

  retrieveRefund: stripeMethod({
    method: 'GET',
    path: '/{chargeId}/refunds/{refundId}',
    urlParams: ['chargeId', 'refundId'],
  }),

  updateRefund: stripeMethod({
    method: 'POST',
    path: '/{chargeId}/refunds/{refundId}',
    urlParams: ['chargeId', 'refundId'],
  }),

  markAsSafe: function(chargeId) {
    return this.update(chargeId, {'fraud_details': {'user_report': 'safe'}})
  },

  markAsFraudulent: function(chargeId) {
    return this.update(chargeId, {'fraud_details': {'user_report': 'fraudulent'}})
  },
});


/***/ }),
/* 36 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: 'country_specs',

  includeBasic: [
    'list', 'retrieve',
  ],
});


/***/ }),
/* 37 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'coupons',
  includeBasic: ['create', 'list', 'update', 'retrieve', 'del'],
});



/***/ }),
/* 38 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'credit_notes',
  includeBasic: ['create', 'list', 'retrieve', 'update'],

  voidCreditNote: stripeMethod({
    method: 'POST',
    path: '{creditNoteId}/void',
    urlParams: ['creditNoteId'],
  }),
});


/***/ }),
/* 39 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var utils = __webpack_require__(2);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'customers',
  includeBasic: [
    'create', 'list', 'retrieve', 'update', 'del',
    'setMetadata', 'getMetadata',
  ],

  /**
   * Customer: Subscription methods
   */

  _legacyUpdateSubscription: stripeMethod({
    method: 'POST',
    path: '{customerId}/subscription',
    urlParams: ['customerId'],
  }),

  _newstyleUpdateSubscription: stripeMethod({
    method: 'POST',
    path: '/{customerId}/subscriptions/{subscriptionId}',
    urlParams: ['customerId', 'subscriptionId'],
  }),

  _legacyCancelSubscription: stripeMethod({
    method: 'DELETE',
    path: '{customerId}/subscription',
    urlParams: ['customerId'],
  }),

  _newstyleCancelSubscription: stripeMethod({
    method: 'DELETE',
    path: '/{customerId}/subscriptions/{subscriptionId}',
    urlParams: ['customerId', 'subscriptionId'],
  }),

  createSubscription: stripeMethod({
    method: 'POST',
    path: '/{customerId}/subscriptions',
    urlParams: ['customerId'],
  }),

  listSubscriptions: stripeMethod({
    method: 'GET',
    path: '/{customerId}/subscriptions',
    urlParams: ['customerId'],
    methodType: 'list',
  }),

  retrieveSubscription: stripeMethod({
    method: 'GET',
    path: '/{customerId}/subscriptions/{subscriptionId}',
    urlParams: ['customerId', 'subscriptionId'],
  }),

  updateSubscription: function(customerId, subscriptionId) {
    if (typeof subscriptionId == 'string') {
      return this._newstyleUpdateSubscription.apply(this, arguments);
    } else {
      return this._legacyUpdateSubscription.apply(this, arguments);
    }
  },

  cancelSubscription: function(customerId, subscriptionId) {
    // This is a hack, but it lets us maximize our overloading.
    // Precarious assumption: If it's not an auth key it _could_ be a sub id:
    if (typeof subscriptionId == 'string' && !utils.isAuthKey(subscriptionId)) {
      return this._newstyleCancelSubscription.apply(this, arguments);
    } else {
      return this._legacyCancelSubscription.apply(this, arguments);
    }
  },

  /**
   * Customer: Card methods
   */

  createCard: stripeMethod({
    method: 'POST',
    path: '/{customerId}/cards',
    urlParams: ['customerId'],
  }),

  listCards: stripeMethod({
    method: 'GET',
    path: '/{customerId}/cards',
    urlParams: ['customerId'],
    methodType: 'list',
  }),

  retrieveCard: stripeMethod({
    method: 'GET',
    path: '/{customerId}/cards/{cardId}',
    urlParams: ['customerId', 'cardId'],
  }),

  updateCard: stripeMethod({
    method: 'POST',
    path: '/{customerId}/cards/{cardId}',
    urlParams: ['customerId', 'cardId'],
  }),

  deleteCard: stripeMethod({
    method: 'DELETE',
    path: '/{customerId}/cards/{cardId}',
    urlParams: ['customerId', 'cardId'],
  }),

  /**
   * Customer: Source methods
   */

  createSource: stripeMethod({
    method: 'POST',
    path: '/{customerId}/sources',
    urlParams: ['customerId'],
  }),

  listSources: stripeMethod({
    method: 'GET',
    path: '/{customerId}/sources',
    urlParams: ['customerId'],
    methodType: 'list',
  }),

  retrieveSource: stripeMethod({
    method: 'GET',
    path: '/{customerId}/sources/{sourceId}',
    urlParams: ['customerId', 'sourceId'],
  }),

  updateSource: stripeMethod({
    method: 'POST',
    path: '/{customerId}/sources/{sourceId}',
    urlParams: ['customerId', 'sourceId'],
  }),

  deleteSource: stripeMethod({
    method: 'DELETE',
    path: '/{customerId}/sources/{sourceId}',
    urlParams: ['customerId', 'sourceId'],
  }),

  verifySource: stripeMethod({
    method: 'POST',
    path: '/{customerId}/sources/{sourceId}/verify',
    urlParams: ['customerId', 'sourceId'],
  }),

  /**
   * Customer: Discount methods
   */

  deleteDiscount: stripeMethod({
    method: 'DELETE',
    path: '/{customerId}/discount',
    urlParams: ['customerId'],
  }),

  deleteSubscriptionDiscount: stripeMethod({
    method: 'DELETE',
    path: '/{customerId}/subscriptions/{subscriptionId}/discount',
    urlParams: ['customerId', 'subscriptionId'],
  }),

  /**
   * Customer: TaxId methods
   */

  createTaxId: stripeMethod({
    method: 'POST',
    path: '/{customerId}/tax_ids',
    urlParams: ['customerId'],
  }),

  deleteTaxId: stripeMethod({
    method: 'DELETE',
    path: '/{customerId}/tax_ids/{taxIdId}',
    urlParams: ['customerId', 'taxIdId'],
  }),

  listTaxIds: stripeMethod({
    method: 'GET',
    path: '/{customerId}/tax_ids',
    urlParams: ['customerId'],
    methodType: 'list',
  }),

  retrieveTaxId: stripeMethod({
    method: 'GET',
    path: '/{customerId}/tax_ids/{taxIdId}',
    urlParams: ['customerId', 'taxIdId'],
  }),
});


/***/ }),
/* 40 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'disputes',

  includeBasic: [
    'list', 'retrieve', 'update', 'setMetadata', 'getMetadata',
  ],

  close: stripeMethod({
    method: 'POST',
    path: '/{id}/close',
    urlParams: ['id'],
  }),

});



/***/ }),
/* 41 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  create: stripeMethod({
    method: 'POST',
    validator: function(data, options) {
      if (!options.headers || !options.headers['Stripe-Version']) {
        throw new Error('stripe_version must be specified to create an ephemeral key');
      }
    },
  }),

  path: 'ephemeral_keys',

  includeBasic: ['del'],
});


/***/ }),
/* 42 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'events',
  includeBasic: ['list', 'retrieve'],
});



/***/ }),
/* 43 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: 'exchange_rates',

  includeBasic: [
    'list', 'retrieve',
  ],
});


/***/ }),
/* 44 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Buffer = __webpack_require__(4).Buffer;
var utils = __webpack_require__(2);
var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;
var multipartDataGenerator = __webpack_require__(45);
var Error = __webpack_require__(3);

module.exports = StripeResource.extend({

  requestDataProcessor: function(method, data, headers, callback) {
    data = data || {};

    if (method === 'POST') {
      return getProcessorForSourceType(data);
    } else {
      return callback(null, utils.stringifyRequestData(data));
    }

    function getProcessorForSourceType(data) {
      var isStream = utils.checkForStream(data);
      if (isStream) {
        return streamProcessor(multipartDataGenerator);
      } else {
        var buffer = multipartDataGenerator(method, data, headers);
        return callback(null, buffer);
      }
    }

    function streamProcessor (fn) {
      var bufferArray = [];
      data.file.data.on('data', function(line) {
        bufferArray.push(line);
      }).on('end', function() {
        var bufferData = Object.assign({}, data);
        bufferData.file.data = Buffer.concat(bufferArray);
        var buffer = fn(method, bufferData, headers);
        callback(null, buffer);
      }).on('error', function(err) {
        var errorHandler = streamError(callback);
        errorHandler(err);
      });
    }

    function streamError(callback) {
      var StreamProcessingError = Error.extend({
        type: 'StreamProcessingError',
        populate: function(raw) {
          this.type = this.type;
          this.message = raw.message;
          this.detail = raw.detail;
        }
      });
      return function(error) {
        callback(
          new StreamProcessingError({
            message: 'An error occurred while attempting to process the file for upload.',
            detail: error,
          }),
          null
        );
      }
    }
  },

  path: 'files',
  includeBasic: ['list', 'retrieve'],

  create: stripeMethod({
    method: 'POST',
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    host: 'files.stripe.com',
  }),
});


/***/ }),
/* 45 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Buffer = __webpack_require__(4).Buffer;
var utils = __webpack_require__(2);

// Method for formatting HTTP body for the multipart/form-data specification
// Mostly taken from Fermata.js
// https://github.com/natevw/fermata/blob/5d9732a33d776ce925013a265935facd1626cc88/fermata.js#L315-L343
function multipartDataGenerator(method, data, headers) {
  var segno = (Math.round(Math.random() * 1e16) + Math.round(Math.random() * 1e16)).toString();
  headers['Content-Type'] = ('multipart/form-data; boundary=' + segno);
  var buffer = Buffer.alloc(0);

  function push(l) {
    var prevBuffer = buffer;
    var newBuffer = (l instanceof Buffer) ? l : Buffer.from(l);
    buffer = Buffer.alloc(prevBuffer.length + newBuffer.length + 2);
    prevBuffer.copy(buffer);
    newBuffer.copy(buffer, prevBuffer.length);
    buffer.write('\r\n', buffer.length - 2);
  }

  function q(s) {
    return '"' + s.replace(/"|"/g, '%22').replace(/\r\n|\r|\n/g, ' ') + '"';
  }

  for (var k in utils.flattenAndStringify(data)) {
    var v = data[k];
    push('--' + segno);
    if (v.hasOwnProperty('data')) {
      push('Content-Disposition: form-data; name=' + q(k) + '; filename=' + q(v.name || 'blob'));
      push('Content-Type: ' + (v.type || 'application/octet-stream'));
      push('');
      push(v.data);
    } else {
      push('Content-Disposition: form-data; name=' + q(k));
      push('');
      push(v);
    }
  }
  push('--' + segno + '--');

  return buffer;
}

module.exports = multipartDataGenerator;


/***/ }),
/* 46 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: 'file_links',
  includeBasic: [
    'create', 'list', 'retrieve', 'update', 'setMetadata', 'getMetadata',
  ],
});


/***/ }),
/* 47 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'invoiceitems',
  includeBasic: [
    'create', 'list', 'retrieve', 'update', 'del',
    'setMetadata', 'getMetadata',
  ],
});



/***/ }),
/* 48 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;
var utils = __webpack_require__(2);

module.exports = StripeResource.extend({

  path: 'invoices',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del'],

  finalizeInvoice: stripeMethod({
    method: 'POST',
    path: '{invoiceId}/finalize',
    urlParams: ['invoiceId'],
  }),

  markUncollectible: stripeMethod({
    method: 'POST',
    path: '{invoiceId}/mark_uncollectible',
    urlParams: ['invoiceId'],
  }),

  pay: stripeMethod({
    method: 'POST',
    path: '{invoiceId}/pay',
    urlParams: ['invoiceId'],
  }),

  retrieveLines: stripeMethod({
    method: 'GET',
    path: '{invoiceId}/lines',
    urlParams: ['invoiceId'],
  }),

  retrieveUpcoming: stripeMethod({
    method: 'GET',
    path: function(urlData) {
      var url = 'upcoming?';
      var hasParam = false;

      // If you pass just a hash with the relevant parameters, including customer id inside.
      if (urlData.invoiceOptionsOrCustomerId && typeof urlData.invoiceOptionsOrCustomerId === 'object') {
        return url + utils.stringifyRequestData(urlData.invoiceOptionsOrCustomerId);
      }

      // Legacy implementation where the first parameter is a customer id as a string
      if (urlData.invoiceOptionsOrCustomerId && typeof urlData.invoiceOptionsOrCustomerId === 'string') {
        url = url + 'customer=' + urlData.invoiceOptionsOrCustomerId;
        hasParam = true;
      }

      // Legacy support where second argument is the subscription id
      if (urlData.invoiceOptionsOrSubscriptionId && typeof urlData.invoiceOptionsOrSubscriptionId === 'string') {
        return url + (hasParam ? '&' : '') + 'subscription=' + urlData.invoiceOptionsOrSubscriptionId;
      } else if (urlData.invoiceOptionsOrSubscriptionId && typeof urlData.invoiceOptionsOrSubscriptionId === 'object') {
        return url + (hasParam ? '&' : '') + utils.stringifyRequestData(urlData.invoiceOptionsOrSubscriptionId);
      }
      return url;
    },
    urlParams: ['optional!invoiceOptionsOrCustomerId', 'optional!invoiceOptionsOrSubscriptionId'],
  }),

  sendInvoice: stripeMethod({
    method: 'POST',
    path: '{invoiceId}/send',
    urlParams: ['invoiceId'],
  }),

  voidInvoice: stripeMethod({
    method: 'POST',
    path: '{invoiceId}/void',
    urlParams: ['invoiceId'],
  }),
});


/***/ }),
/* 49 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'issuer_fraud_records',

  includeBasic: ['list', 'retrieve'],
});


/***/ }),
/* 50 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'accounts/{accountId}/login_links',
  includeBasic: ['create'],
});


/***/ }),
/* 51 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;
var utils = __webpack_require__(2);

var oAuthHost = 'connect.stripe.com';

module.exports = StripeResource.extend({
  basePath: '/',

  authorizeUrl: function(params, options) {
    params = params || {};
    options = options || {};

    var path = 'oauth/authorize';

    // For Express accounts, the path changes
    if (options.express) {
      path = 'express/' + path;
    }

    if (!params.response_type) {
      params.response_type = 'code';
    }

    if (!params.client_id) {
      params.client_id = this._stripe.getClientId();
    }

    if (!params.scope) {
      params.scope = 'read_write';
    }

    return 'https://' + oAuthHost + '/' + path + '?' + utils.stringifyRequestData(params);
  },

  token: stripeMethod({
    method: 'POST',
    path: 'oauth/token',
    host: oAuthHost,
  }),

  deauthorize: function(spec) {
    if (!spec.client_id) {
      spec.client_id = this._stripe.getClientId();
    }

    return stripeMethod({
      method: 'POST',
      path: 'oauth/deauthorize',
      host: oAuthHost,
    }).apply(this, arguments);
  },
});


/***/ }),
/* 52 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: 'order_returns',

  includeBasic: [
    'list', 'retrieve',
  ],
});


/***/ }),
/* 53 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'orders',

  includeBasic: [
    'create', 'list', 'retrieve', 'update',
  ],

  pay: stripeMethod({
    method: 'POST',
    path: '/{orderId}/pay',
    urlParams: ['orderId'],
  }),

  returnOrder: stripeMethod({
    method: 'POST',
    path: '/{orderId}/returns',
    urlParams: ['orderId'],
  }),

});


/***/ }),
/* 54 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  path: 'payment_intents',
  includeBasic: ['create', 'list', 'retrieve', 'update'],

  cancel: stripeMethod({
    method: 'POST',
    path: '{paymentIntentId}/cancel',
    urlParams: ['paymentIntentId'],
  }),

  capture: stripeMethod({
    method: 'POST',
    path: '{paymentIntentId}/capture',
    urlParams: ['paymentIntentId'],
  }),

  confirm: stripeMethod({
    method: 'POST',
    path: '{paymentIntentId}/confirm',
    urlParams: ['paymentIntentId'],
  }),
});



/***/ }),
/* 55 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'payment_methods',
  includeBasic: ['create', 'list', 'retrieve', 'update'],

  attach: stripeMethod({
    method: 'POST',
    path: '{paymentMethodId}/attach',
    urlParams: ['paymentMethodId'],
  }),

  detach: stripeMethod({
    method: 'POST',
    path: '{paymentMethodId}/detach',
    urlParams: ['paymentMethodId'],
  }),
});


/***/ }),
/* 56 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'payouts',

  includeBasic: [
    'create', 'list', 'retrieve', 'update',
    'setMetadata', 'getMetadata',
  ],

  cancel: stripeMethod({
    method: 'POST',
    path: '{payoutId}/cancel',
    urlParams: ['payoutId'],
  }),

  listTransactions: stripeMethod({
    method: 'GET',
    path: '{payoutId}/transactions',
    urlParams: ['payoutId'],
    methodType: 'list',
  }),
});



/***/ }),
/* 57 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'plans',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del'],
});



/***/ }),
/* 58 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: 'products',

  includeBasic: [
    'create', 'list', 'retrieve', 'update', 'del',
  ],

});


/***/ }),
/* 59 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * RecipientCard is similar to CustomerCard in that, upon instantiation, it
 * requires a recipientId, and therefore each of its methods only
 * require the cardId argument.
 *
 * This streamlines the API specifically for the case of accessing cards
 * on a returned recipient object.
 *
 * E.g. recipientObject.cards.retrieve(cardId)
 * (As opposed to the also-supported stripe.recipients.retrieveCard(recipientId, cardId))
 */
module.exports = StripeResource.extend({
  path: 'recipients/{recipientId}/cards',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del'],
});


/***/ }),
/* 60 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'recipients',
  includeBasic: [
    'create', 'list', 'retrieve', 'update', 'del',
    'setMetadata', 'getMetadata',
  ],

  createCard: stripeMethod({
    method: 'POST',
    path: '/{recipientId}/cards',
    urlParams: ['recipientId'],
  }),

  listCards: stripeMethod({
    method: 'GET',
    path: '/{recipientId}/cards',
    urlParams: ['recipientId'],
    methodType: 'list',
  }),

  retrieveCard: stripeMethod({
    method: 'GET',
    path: '/{recipientId}/cards/{cardId}',
    urlParams: ['recipientId', 'cardId'],
  }),

  updateCard: stripeMethod({
    method: 'POST',
    path: '/{recipientId}/cards/{cardId}',
    urlParams: ['recipientId', 'cardId'],
  }),

  deleteCard: stripeMethod({
    method: 'DELETE',
    path: '/{recipientId}/cards/{cardId}',
    urlParams: ['recipientId', 'cardId'],
  }),

});



/***/ }),
/* 61 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: 'refunds',

  includeBasic: [
    'create', 'list', 'retrieve', 'update',
  ],
});



/***/ }),
/* 62 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'reviews',

  includeBasic: ['list', 'retrieve'],

  approve: stripeMethod({
    method: 'POST',
    path: '/{id}/approve',
    urlParams: ['id'],
  }),
});



/***/ }),
/* 63 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: 'skus',

  includeBasic: [
    'create', 'list', 'retrieve', 'update', 'del',
  ],

});


/***/ }),
/* 64 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'sources',

  includeBasic: [
    'create', 'retrieve', 'update', 'setMetadata', 'getMetadata',
  ],

  listSourceTransactions: stripeMethod({
    method: 'GET',
    path: '/{id}/source_transactions',
    urlParams: ['id'],
    methodType: 'list',
  }),

  verify: stripeMethod({
    method: 'POST',
    path: '/{id}/verify',
    urlParams: ['id'],
  }),

});


/***/ }),
/* 65 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'subscription_items',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del',],
});



/***/ }),
/* 66 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'subscription_schedules',

  includeBasic: [
    'create', 'list', 'retrieve', 'update',
    'setMetadata', 'getMetadata',
  ],

  release: stripeMethod({
    method: 'POST',
    path: '/{id}/release',
    urlParams: ['id'],
  }),

  cancel: stripeMethod({
    method: 'POST',
    path: '/{id}/cancel',
    urlParams: ['id'],
  }),

  /**
   * SubscriptionSchedules: SubscriptionScheduleRevisions methods
   */

  listRevisions: stripeMethod({
    method: 'GET',
    path: '/{scheduleId}/revisions',
    urlParams: ['scheduleId'],
    methodType: 'list',
  }),

  retrieveRevision: stripeMethod({
    method: 'GET',
    path: '/{scheduleId}/revisions/{revisionId}',
    urlParams: ['scheduleId', 'revisionId'],
  }),
});


/***/ }),
/* 67 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'subscriptions',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del',],

  /**
   * Subscription: Discount methods
   */
  deleteDiscount: stripeMethod({
    method: 'DELETE',
    path: '/{subscriptionId}/discount',
    urlParams: ['subscriptionId'],
  }),
});


/***/ }),
/* 68 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'tax_rates',
  includeBasic: ['create', 'list', 'update', 'retrieve'],
});



/***/ }),
/* 69 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({

  path: '3d_secure',

  includeBasic: [
    'create',
    'retrieve',
  ],
});


/***/ }),
/* 70 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'tokens',
  includeBasic: ['create', 'retrieve'],
});


/***/ }),
/* 71 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  path: 'topups',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'setMetadata', 'getMetadata'],

  cancel: stripeMethod({
    method: 'POST',
    path: '{topupId}/cancel',
    urlParams: ['topupId'],
  }),
});


/***/ }),
/* 72 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({

  path: 'transfers',

  includeBasic: [
    'create', 'list', 'retrieve', 'update',
    'setMetadata', 'getMetadata',
  ],

  reverse: stripeMethod({
    method: 'POST',
    path: '/{transferId}/reversals',
    urlParams: ['transferId'],
  }),

  cancel: stripeMethod({
    method: 'POST',
    path: '{transferId}/cancel',
    urlParams: ['transferId'],
  }),

  listTransactions: stripeMethod({
    method: 'GET',
    path: '{transferId}/transactions',
    urlParams: ['transferId'],
    methodType: 'list',
  }),

  /**
   * Transfer: Reversal methods
   */
  createReversal: stripeMethod({
    method: 'POST',
    path: '/{transferId}/reversals',
    urlParams: ['transferId'],
  }),

  listReversals: stripeMethod({
    method: 'GET',
    path: '/{transferId}/reversals',
    urlParams: ['transferId'],
    methodType: 'list',
  }),

  retrieveReversal: stripeMethod({
    method: 'GET',
    path: '/{transferId}/reversals/{reversalId}',
    urlParams: ['transferId', 'reversalId'],
  }),

  updateReversal: stripeMethod({
    method: 'POST',
    path: '/{transferId}/reversals/{reversalId}',
    urlParams: ['transferId', 'reversalId'],
  }),
});



/***/ }),
/* 73 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  path: 'subscription_items',

  create: stripeMethod({
    method: 'POST',
    path: '{subscriptionItem}/usage_records',
    urlParams: ['subscriptionItem'],
  }),
});


/***/ }),
/* 74 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  path: 'subscription_items',

  list: stripeMethod({
    method: 'GET',
    path: '{subscriptionItem}/usage_record_summaries',
    urlParams: ['subscriptionItem'],
    methodType: 'list',
  }),
});


/***/ }),
/* 75 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(1).extend({
  path: 'webhook_endpoints',
  includeBasic: ['create', 'list', 'update', 'retrieve', 'del'],
});



/***/ }),
/* 76 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * ApplicationFeeRefunds is a unique resource in that, upon instantiation,
 * requires an application fee id , and therefore each of its methods only
 * require the refundId argument.
 *
 * This streamlines the API specifically for the case of accessing refunds
 * on a returned application fee object.
 *
 * E.g. applicationFeeObject.refunds.retrieve(refundId)
 * (As opposed to the also-supported stripe.applicationFees.retrieveRefund(chargeId,
 * refundId))
 */
module.exports = StripeResource.extend({
  path: 'application_fees/{feeId}/refunds',
  includeBasic: ['create', 'list', 'retrieve', 'update'],
});


/***/ }),
/* 77 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * ChargeRefunds is a unique resource in that, upon instantiation,
 * requires a chargeId, and therefore each of its methods only
 * require the refundId argument.
 *
 * This streamlines the API specifically for the case of accessing refunds
 * on a returned charge object.
 *
 * E.g. chargeObject.refunds.retrieve(refundId)
 * (As opposed to the also-supported stripe.charges.retrieveRefund(chargeId,
 * refundId))
 */
module.exports = StripeResource.extend({
  path: 'charges/{chargeId}/refunds',
  includeBasic: ['create', 'list', 'retrieve', 'update'],
});


/***/ }),
/* 78 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * CustomerCard is a unique resource in that, upon instantiation,
 * requires a customerId, and therefore each of its methods only
 * require the cardId argument.
 *
 * This streamlines the API specifically for the case of accessing cards
 * on a returned customer object.
 *
 * E.g. customerObject.cards.retrieve(cardId)
 * (As opposed to the also-supported stripe.customers.retrieveCard(custId, cardId))
 */
module.exports = StripeResource.extend({
  path: 'customers/{customerId}/cards',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del'],
});


/***/ }),
/* 79 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

/**
 * CustomerSubscription is a unique resource in that, upon instantiation,
 * requires a customerId, and therefore each of its methods only
 * require the subscriptionId argument.
 *
 * This streamlines the API specifically for the case of accessing cards
 * on a returned customer object.
 *
 * E.g. customerObject.cards.retrieve(cardId)
 * (As opposed to the also-supported stripe.customers.retrieveCard(custId, cardId))
 */
module.exports = StripeResource.extend({
  path: 'customers/{customerId}/subscriptions',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del'],

  /**
   * Customer: Discount methods
   */

  deleteDiscount: stripeMethod({
    method: 'DELETE',
    path: '/{subscriptionId}/discount',
    urlParams: ['customerId', 'subscriptionId'],
  }),
});


/***/ }),
/* 80 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * Persons is a unique resource in that, upon instantiation,
 * requires an accountId, and therefore each of its methods only
 * require the personId argument.
 *
 * This streamlines the API specifically for the case of accessing person
 * on a returned transfer object.
 *
 * E.g. accountObject.person.retrieve(personId)
 * (As opposed to the also-supported stripe.accounts.retrievePerson(accountId,
 * personId))
 */
module.exports = StripeResource.extend({
  path: 'accounts/{accountId}/persons',
  includeBasic: ['create', 'del', 'list', 'retrieve', 'update'],
});



/***/ }),
/* 81 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * SubscriptionScheduleRevisions is a unique resource in that, upon instantiation,
 * requires a subscription schedule id, and therefore each of its methods only
 * require the scheduleId argument.
 *
 * This streamlines the API specifically for the case of accessing a revision
 * on a returned subscription schedule object.
 *
 * E.g. scheduleObject.revisions.retrieve(revisionId)
 * (As opposed to the also-supported stripe.subscriptionSchedules.retrieveRevision(scheduleId,
 * revisionId))
 */
module.exports = StripeResource.extend({
  path: 'subscription_schedules/{scheduleId}/revisions',
  includeBasic: ['list', 'retrieve',],
});


/***/ }),
/* 82 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * TaxIds is a unique resource in that, upon instantiation,
 * requires a customerId, and therefore each of its methods only
 * require the taxId argument.
 *
 * This streamlines the API specifically for the case of accessing a tax id
 * on a returned customer object.
 *
 * E.g. customerObject.tax_ids.retrieve(taxIdId)
 * (As opposed to the also-supported stripe.customers.retrieveTaxId(customerId, taxIdId))
 */
module.exports = StripeResource.extend({
  path: 'customers/{customerId}/tax_ids',
  includeBasic: ['create', 'del', 'list', 'retrieve'],
});


/***/ }),
/* 83 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

/**
 * TransferReversals is a unique resource in that, upon instantiation,
 * requires a transferId, and therefore each of its methods only
 * require the reversalId argument.
 *
 * This streamlines the API specifically for the case of accessing reversals
 * on a returned transfer object.
 *
 * E.g. transferObject.reversals.retrieve(reversalId)
 * (As opposed to the also-supported stripe.transfers.retrieveReversal(transferId,
 * reversalId))
 */
module.exports = StripeResource.extend({
  path: 'transfers/{transferId}/reversals',
  includeBasic: ['create', 'list', 'retrieve', 'update'],
});



/***/ }),
/* 84 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'checkout/sessions',
  includeBasic: ['create', 'retrieve'],
})


/***/ }),
/* 85 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  path: 'issuing/authorizations',

  includeBasic: ['list', 'retrieve', 'update', 'setMetadata', 'getMetadata'],

  approve: stripeMethod({
    method: 'POST',
    path: '/{id}/approve',
    urlParams: ['id'],
  }),

  decline: stripeMethod({
    method: 'POST',
    path: '/{id}/decline',
    urlParams: ['id'],
  }),
});


/***/ }),
/* 86 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'issuing/cardholders',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'setMetadata', 'getMetadata'],
});


/***/ }),
/* 87 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);
var stripeMethod = StripeResource.method;

module.exports = StripeResource.extend({
  path: 'issuing/cards',

  includeBasic: ['create', 'list', 'retrieve', 'update', 'setMetadata', 'getMetadata'],

  retrieveDetails: stripeMethod({
    method: 'GET',
    path: '/{id}/details',
    urlParams: ['id'],
  }),
});


/***/ }),
/* 88 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'issuing/disputes',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'setMetadata', 'getMetadata'],
});


/***/ }),
/* 89 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'issuing/transactions',
  includeBasic: ['list', 'retrieve', 'update', 'setMetadata', 'getMetadata'],
});


/***/ }),
/* 90 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'radar/value_lists',
  includeBasic: ['create', 'list', 'update', 'retrieve', 'del'],
});


/***/ }),
/* 91 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'radar/value_list_items',
  includeBasic: ['create', 'list', 'retrieve', 'del'],
});


/***/ }),
/* 92 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'reporting/report_runs',
  includeBasic: ['create', 'list', 'retrieve'],
});


/***/ }),
/* 93 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'reporting/report_types',
  includeBasic: ['list', 'retrieve'],
});


/***/ }),
/* 94 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'sigma/scheduled_query_runs',

  includeBasic: ['list', 'retrieve'],
});


/***/ }),
/* 95 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'terminal/connection_tokens',
  includeBasic: ['create'],
})


/***/ }),
/* 96 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'terminal/locations',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del'],
})


/***/ }),
/* 97 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var StripeResource = __webpack_require__(1);

module.exports = StripeResource.extend({
  path: 'terminal/readers',
  includeBasic: ['create', 'list', 'retrieve', 'update', 'del'],
})


/***/ })
/******/ ])));