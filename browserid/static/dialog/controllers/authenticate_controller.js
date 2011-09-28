/*jshint browser:true, jQuery: true, forin: true, laxbreak:true */
/*global BrowserIDIdentities: true, BrowserIDNetwork: true, BrowserIDWait:true, BrowserIDErrors: true, PageController: true */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla BrowserID.
 *
 * The Initial Developer of the Original Code is Mozilla.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
(function() {
  "use strict";

  // XXX - Push what we can of BrowserIDNetwork into BrowserIDIdentities.
  
  var ANIMATION_TIME = 250,
      network = BrowserIDNetwork,
      identities = BrowserIDIdentities;

  function animateSwap(fadeOutSelector, fadeInSelector, callback) {
    $(fadeOutSelector).fadeOut(ANIMATION_TIME, function() {
      $(fadeInSelector).fadeIn(ANIMATION_TIME, callback);
    });
  }

  PageController.extend("Authenticate", {}, {
    init: function() {
      this._super({
        bodyTemplate: "authenticate.ejs",
        bodyVars: {
          sitename: identities.getOrigin(),
          siteicon: '/i/times.gif'
        }
      });
      this.submitAction = "checkEmail";
    },

    "#email click" : function(el, event) {
      if (!el.is(":disabled")) {
        this.submitAction = "checkEmail";
        animateSwap(".returning:visible,.newuser:visible", ".start");
      }
    },

    "#forgotPassword click": function(el, event) {
      event.preventDefault();

      this.submitAction = "resetPassword";
      $("#email").attr("disabled", "disabled");

      animateSwap(".returning", ".forgot");
    },

    '#cancel_forgot_password click': function(el, event) {
      event.preventDefault();

      this.submitAction = "authenticate";
      $("#email").removeAttr("disabled");
      animateSwap(".forgot", ".returning", function() {
        $("#password").focus();
      });
    },

    submit: function() {
      this[this.submitAction]();
    },

    checkEmail: function() {
      var email = $("#email").val(),
          self = this;

      if(!email) {
        // XXX error screen
        return;
      }

      // XXX verify email length/format here
      // show error message if bad.
      network.emailRegistered(email, function onComplete(registered) {
        // XXX instead of using jQuery here, think about using CSS animations.
        $(".start").fadeOut(function() {
          if(registered) {
            self.submitAction = "authenticate";
            animateSwap(".newuser", ".returning", function() {
              $("#password").focus();  
            });
          }
          else {
            self.submitAction = "createUser";
            animateSwap(".returning", ".newuser");
          }
        });
      });
    },

    createUser: function() {
      var self=this,
          email = $("#email").val();

      if(!email) {
        // XXX error screen
        return;
      }

      identities.createUser(email, function(keypair) {
        if(keypair) {
          self.close("user_staged", {
            email: email,
            keypair: keypair
          });
        }
        else {
          // XXX can't register this email address.
        }
      }, self.getErrorDialog(BrowserIDErrors.createAccount));
    },

    authenticate: function() {
      var email = $("#email").val(),
          pass = $("#password").val(),
          self = this;

      if(!(email && pass)) {
        // XXX error screen
        return;
      }

      identities.authenticateAndSync(email, pass, 
        function onAuthenticate(authenticated) {
          if (authenticated) {
            self.doWait(BrowserIDWait.authentication);
          } 
          else {
            // XXX error screen
          }
        },
        function onComplete(authenticated) {
          if (authenticated) {
            self.close("authenticated");
          } else {
            // XXX error screen.
          }
        }, 
        self.getErrorDialog(BrowserIDErrors.authentication)
      );

    },

    resetPassword: function() {
      var email = $("#email").val();
      var me=this;
      network.requestPasswordReset(email, function(reset) {
        if (reset) {
          me.close("reset_password", {
            email: email
          });
        }
        else {
          // XXX error screen.
        }
      }, function onFailure() {

      });
    }
  });

}());
