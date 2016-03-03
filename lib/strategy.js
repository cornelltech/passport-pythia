var passport = require('passport-strategy');
var util = require('util');
var lookup = require('./utils').lookup;


/**
 * `Strategy` constructor.
 *
 * The pythia authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `userLookup` callback which accepts `username`,
 * looks up the user object for the username, and then calls the `done` callback
 * supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *
 * Examples:
 *

 * passport.use(new PythiaStrategy(
 *   function(username, callback) {
 *     return User.findOne({ username: username }, callback);
 *   }
 * ));
 *
 * @param {Object} options
 * @param {Function} userLookup
 * @api public
 */

function Strategy(options, userLookup) {

  console.log('initializing pythia strategy');
  if (typeof options == 'function') {
    userLookup = options;
    options = {};
  }
  if (!userLookup) { throw new TypeError('PythiaStrategy requires a user lookup callback'); }

  this._usernameField = options.usernameField || 'username';
  this._passwordField = options.passwordField || 'password';

  passport.Strategy.call(this);
  this.name = 'pythia';
  this._userLookup = userLookup;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */

Strategy.prototype.authenticate = function(req) {

  var username = lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField);
  var password = lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField);

  if (!username || !password) {
    return this.fail({ message: 'Missing credentials' }, 400);
  }

  var self = this;

  function verifyUser(err, user) {

   if (err) { return self.error(err); }
   if (!user) { return self.fail({ message: 'Incorrect username.' }); }

   try {
     user.comparePassword(password, function(err, match) {
       if (err) { return self.error(err); }
       if (!match) {
        return self.fail({ message: 'Incorrect password.' });
       }
       else {
         return self.success(user, null);
       }
     });
   } catch (ex) {
     return self.error(ex);
   }
  }

  try {
    this._userLookup(username, verifyUser);
  } catch (ex) {
    return self.error(ex);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
