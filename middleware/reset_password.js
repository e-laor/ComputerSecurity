const bcrypt = require('bcrypt');

async function reset_password (req, res, next) {
    const { password, confirm_password, email } = req.body;
    const user = await User.findOne({ where: { email: email } });
  
    try {
      if (!user) {
        req.flash("error", "User not found.");
        return res.render("reset-password", {
          title: "Reset Password",
          email: email,
          error: req.flash("error"),
        });
      }
  
      if (password !== confirm_password) {
        req.flash("error", "Passwords do not match");
        return res.render("reset-password", {
          title: "Reset Password",
          email: email,
          error: req.flash("error"),
        });
      }
      if (!password || !confirm_password) {
        req.flash("error", "Passwords can't be empty");
        return res.render("reset-password", {
          title: "Reset Password",
          email: email,
          error: req.flash("error"),
        });
      }
  
      // Check password strength
      const isValidPassword = pass_secure.isPasswordStrong(password);
  
      // If password isn't strong enough return an error with the message
      if (!isValidPassword.isValid) {
        req.flash("error", isValidPassword.message);
        return res.render("reset-password", {
          title: "Reset Password",
          email: email,
          error: req.flash("error"),
        });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();
  
      req.session.allowAccess = false; // Clear session variable to prevent further access
      return res.redirect("/reset-password-success"); // Redirect to success page
    } catch (error) {
      req.flash("error", error.message);
      return res.render("reset-password", {
        title: "Reset Password",
        email: email,
        error: req.flash("error"),
      });
    }
  }

  module.exports = reset_password;