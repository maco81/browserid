/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const
metrics = require('../metrics.js'),
url = require('url'),
logger = require('../logging.js').logger,
fs = require('fs'),
connect = require('connect'),
config = require('../configuration.js'),
und = require('../jwcrypto/underscore'),
util = require('util');

// all templated content, redirects, and renames are handled here.
// anything that is not an api, and not static
const
path = require('path');


const VIEW_PATH = path.join(__dirname, "..", "..", "resources", "views");

// none of our views include dynamic data.  all of them should be served
// with reasonable cache headers.  This wrapper around rendering handles
// cache headers maximally leveraging the same logic that connect uses
// issue #910
function renderCachableView(req, res, template, options) {
  fs.stat(path.join(VIEW_PATH, template), function (err, stat) {
    res.setHeader('Date', new Date().toUTCString());
    res.setHeader('Vary', 'Accept-Encoding,Accept-Language');
    if (config.get('env') !== 'local') {
      // allow caching, but require revalidation via ETag
      res.setHeader('Cache-Control', 'public, max-age=0');
      res.setHeader('ETag', util.format('"%s-%s-%s"', stat.size, Number(stat.mtime), req.lang));
    } else {
      res.setHeader('Cache-Control', 'no-store');
    }
    res.setHeader('Content-Type', 'text/html; charset=utf8');
    if (connect.utils.conditionalGET(req)) {
      if (!connect.utils.modified(req, res)) {
        return connect.utils.notModified(res);
      }
    }
    res.render(template, options);
  });
}

exports.setup = function(app) {
  app.set("views", VIEW_PATH);

  app.set('view options', {
    production: config.get('use_minified_resources')
  });

  app.get('/include.js', function(req, res, next) {
    req.url = "/include_js/include.js";

    if (config.get('use_minified_resources') === true) {
      req.url = "/production/include.js"
    }

    next();
  });

  app.get('/include.orig.js', function(req, res, next) {
    req.url = "/include_js/include.js";
    next();
  });

  // this should probably be an internal redirect
  // as soon as relative paths are figured out.
  app.get('/sign_in', function(req, res, next ) {
    metrics.userEntry(req);
    renderCachableView(req, res, 'dialog.ejs', {
      title: 'A Better Way to Sign In',
      layout: 'dialog_layout.ejs',
      useJavascript: true,
      production: config.get('use_minified_resources')
    });
  });

  app.get('/communication_iframe', function(req, res, next ) {
    res.removeHeader('x-frame-options');
    renderCachableView(req, res, 'communication_iframe.ejs', {
      layout: false,
      production: config.get('use_minified_resources')
    });
  });

  app.get("/unsupported_dialog", function(req,res) {
    renderCachableView(req, res, 'unsupported_dialog.ejs', {layout: 'dialog_layout.ejs', useJavascript: false});
  });

  // Used for a relay page for communication.
  app.get("/relay", function(req, res, next) {
    // Allow the relay to be run within a frame
    res.removeHeader('x-frame-options');
    renderCachableView(req, res, 'relay.ejs', {
      layout: false,
      production: config.get('use_minified_resources')
    });
  });

  app.get("/authenticate_with_primary", function(req,res, next) {
    renderCachableView(req, res, 'authenticate_with_primary.ejs', { layout: false });
  });

  app.get('/', function(req,res) {
    renderCachableView(req, res, 'index.ejs', {title: 'A Better Way to Sign In', fullpage: true});
  });

  app.get("/signup", function(req, res) {
    renderCachableView(req, res, 'signup.ejs', {title: 'Sign Up', fullpage: false});
  });

  app.get("/idp_auth_complete", function(req, res) {
    renderCachableView(req, res, 'idp_auth_complete.ejs', {
      title: 'Sign In Complete',
      fullpage: false
    });
  });

  app.get("/forgot", function(req, res) {
    // !cachable!  email embedded in DOM
    res.render('forgot.ejs', {title: 'Forgot Password', fullpage: false, email: req.query.email});
  });

  app.get("/signin", function(req, res) {
    renderCachableView(req, res, 'signin.ejs', {title: 'Sign In', fullpage: false});
  });

  app.get("/about", function(req, res) {
    renderCachableView(req, res, 'about.ejs', {title: 'About', fullpage: false});
  });

  app.get("/tos", function(req, res) {
    renderCachableView(req, res, 'tos.ejs', {title: 'Terms of Service', fullpage: false});
  });

  app.get("/privacy", function(req, res) {
    renderCachableView(req, res, 'privacy.ejs', {title: 'Privacy Policy', fullpage: false});
  });

  app.get("/verify_email_address", function(req, res) {
    // !cachable!  token is embedded in DOM
    res.render('verify_email_address.ejs', {title: 'Complete Registration', fullpage: true, token: req.query.token});
  });

  app.get("/add_email_address", function(req,res) {
    renderCachableView(req, res, 'add_email_address.ejs', {title: 'Verify Email Address', fullpage: false});
  });

  /**
   *
   * XXX benadida or lloyd, I tried to use straight up regexp to do this, but.
   * is there a better way to do this?
   */
  function QUnit(req, res) {
    res.render('test.ejs', {title: 'BrowserID QUnit Test', layout: false});
  }

  app.get("/test", QUnit);
  app.get("/test/index.html", QUnit);

  // REDIRECTS
  REDIRECTS = {
    "/manage": "/",
    "/users": "/",
    "/users/": "/",
    "/primaries" : "/developers",
    "/primaries/" : "/developers",
    "/developers" : "https://github.com/mozilla/browserid/wiki/How-to-Use-BrowserID-on-Your-Site"
  };

  // set up all the redirects
  // oh my watch out for scope issues on var url - closure time
  for (var url in REDIRECTS) {
    (function(from,to) {
      app.get(from, function(req, res) {
        res.redirect(to);
      });
    })(url, REDIRECTS[url]);
  }

  try {
    const publicKey = secrets.loadPublicKey();
  } catch(e){
    logger.error("can't read public key, exiting: " + e);
    process.nextTick(function() { process.exit(1); });
  }

  // the public key (This location is DEPRECATED)
  app.get("/pk", function(req, res) {
    res.json(publicKey.toSimpleObject());
  });

  // the "declaration of support" style publishing of the public key.
  // BrowserID.org is a (uh, THE) secondary, it should publish its key
  // in a manner that is symmetric with how primaries do.  At present,
  // the absence of 'provisioning' and 'authentication' keys indicates
  // that this is a secondary, and verifiers should only trust
  // browserid.org as a secondary (and anyone else they decide to for
  // whatever reason).
  app.get("/.well-known/browserid", function(req, res) {
    res.json({ 'public-key': publicKey.toSimpleObject() });
  });

  // now for static redirects for cach busting - issue #225
  var versionRegex = /^(\/production\/[a-zA-Z\-]+)_v[a-zA-Z0-9]{7}(\.(?:css|js))$/;
  app.use(function(req, res, next) {
    var m = versionRegex.exec(req.url);
    if (m) {
      var newURL = m[1] + m[2];
      logger.debug('internal redirect of ' + req.url + ' to ' + newURL);
      req.url = newURL;
    }
    next();
  });
};

// Common to browserid.js dialog.js
var common1 = function (locale) {
  return [
    "/lib/jquery-1.7.1.min.js",
    "/lib/winchan.js",
    "/lib/underscore-min.js",
    "/lib/vepbundle.js",
    "/lib/ejs.js",
    "/shared/javascript-extensions.js",
    util.format("/i18n/%s/client.json", locale),
    "/shared/gettext.js",
    "/shared/browserid.js",
    "/lib/hub.js",
    "/lib/dom-jquery.js",
    "/lib/module.js",
    "/lib/jschannel.js",
    "/shared/templates.js",
    "/shared/renderer.js",
    "/shared/class.js",
    "/shared/mediator.js",
    "/shared/tooltip.js",
    "/shared/validation.js",
    "/shared/helpers.js",
    "/shared/screens.js",
    "/shared/browser-support.js",
    "/shared/wait-messages.js",
    "/shared/error-messages.js",
    "/shared/error-display.js",
    "/shared/storage.js",
    "/shared/xhr.js",
    "/shared/network.js",
    "/shared/provisioning.js",
    "/shared/user.js"
  ];
};
// Common to browserid.js dialog.js
var common2 = [
  "/shared/modules/page_module.js",
  "/shared/modules/xhr_delay.js",
  "/shared/modules/xhr_disable_form.js",
  "/shared/modules/cookie_check.js"
];

/**
 * Cachify compatible mapping of JavaScript source and 
 * production build files.
 */
exports.js = function(langs) {
  var js_files = {};
  und.each(langs, function (lang) {
    var locale = i18n.localeFrom(lang),
        browserid_js,
        dialog_js;

    browserid_js = util.format("/production/%s/browserid.js", locale),
    js_files[browserid_js] = und.flatten([
      common1(locale),
      common2,
      [
          "/pages/page_helpers.js",
          "/pages/index.js",
          "/pages/start.js",
          "/pages/add_email_address.js",
          "/pages/verify_email_address.js",
          "/pages/forgot.js",
          "/pages/manage_account.js",
          "/pages/signin.js",
          "/pages/signup.js"
      ]]);

    dialog_js = util.format("/production/%s/dialog.js", locale);
    js_files[dialog_js] = und.flatten([
      common1(locale),
      [
          "/shared/command.js",
          "/shared/history.js",
          "/shared/state_machine.js"
      ],
      common2,
      [
          "/dialog/resources/internal_api.js",
          "/dialog/resources/helpers.js",
          "/dialog/resources/state.js",
        
          "/dialog/controllers/actions.js",
          "/dialog/controllers/dialog.js",
          "/dialog/controllers/authenticate.js",
          "/dialog/controllers/forgot_password.js",
          "/dialog/controllers/check_registration.js",
          "/dialog/controllers/pick_email.js",
          "/dialog/controllers/add_email.js",
          "/dialog/controllers/required_email.js",
          "/dialog/controllers/verify_primary_user.js",
          "/dialog/controllers/provision_primary_user.js",
          "/dialog/controllers/primary_user_provisioned.js",
          "/dialog/controllers/email_chosen.js",

          "/dialog/start.js"
      ]]);
  });
  return js_files;
};


