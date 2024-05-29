// used for handling account login

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../model/User'); 


passport.use(
  new LocalStrategy(
    {
      passReqToCallback: true,
    },
    async (req, username, password, done) => {
      try {
        const user = await User.findOne({ where: { username: username } });
        if (!user) {
          return done(null, false, { message: "Incorrect username." });
        }

        // Check if the account is locked
        if (user.isLocked) {
          return done(null, false, {
            message: "Account is locked. Please contact support.",
          });
        }

        // Check if the account is locked due to too many failed attempts
        if (req.session.failedLoginAttempts >= 3) {
          // Lock the account
          user.isLocked = true;
          await user.save();
          return done(null, false, {
            message: "Account locked due to too many failed login attempts. Please contact support.",
          });
        }

        const isValidPassword = await user.validPassword(password);
        if (!isValidPassword) {
          // Increment failed login attempts on failure
          req.session.failedLoginAttempts = (req.session.failedLoginAttempts || 0) + 1;
          if (req.session.failedLoginAttempts >= 3) {
            // Lock the account
            user.isLocked = true;
            await user.save();
          }
          return done(null, false, { message: "Incorrect password." });
        }

        // Reset failed login attempts on successful login
        req.session.failedLoginAttempts = 0;

        return done(null, user); // If authentication succeeds
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = passport;