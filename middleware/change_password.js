const bcrypt = require('bcrypt');
const User = require("../model/User");
const PasswordHistory = require('../model/PasswordHistory');
const pass_secure = require("../security/pass_security");

async function change_password(req, res, next) {
  const { password, confirm_password, email } = req.body;
  const user = await User.findOne({ where: { email: email } });

  try {
    if (!user) {
      req.flash("error", "User not found.");
      return res.render("change_password", {
        title: "Change Password",
        email: email,
        error: req.flash("error"),
      });
    }

    if (password !== confirm_password) {
      req.flash("error", "Passwords do not match");
      return res.render("change_password", {
        title: "Change Password",
        email: email,
        error: req.flash("error"),
      });
    }
    if (!password || !confirm_password) {
      req.flash("error", "Passwords can't be empty");
      return res.render("change_password", {
        title: "Change Password",
        email: email,
        error: req.flash("error"),
      });
    }

    // Check password strength
    const isValidPassword = pass_secure.isPasswordStrong(password);

    // If password isn't strong enough return an error with the message
    if (!isValidPassword.isValid) {
      req.flash("error", isValidPassword.message);
      return res.render("change_password", {
        title: "Change Password",
        email: email,
        error: req.flash("error"),
      });
    }

    // Retrieve the user's password history
    const userPasswordHistory = await PasswordHistory.findAll({
      where: { userId: user.id },
      order: [['changeDate', 'DESC']],
      limit: 3 // Get the last 3 password changes
    });

    // Hash the new password
    const newPasswordHash = await bcrypt.hash(password, 10);
    
    // Check if the new password matches any of the last 3 passwords
    const passwordMatch = userPasswordHistory.some(entry => {
      return bcrypt.compareSync(password, entry.password);
    });

    if (passwordMatch) {
      req.flash("error", "Cannot use the same password as before.");
      return res.render("change_password", {
        title: "Change Password",
        email: email,
        error: req.flash("error"),
      });
    }

    // Update the user's password
    user.password = newPasswordHash;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    // Add the new password to the password history table
    await PasswordHistory.create({ userId: user.id, password: newPasswordHash });

    req.session.allowAccess = false; // Clear session variable to prevent further access
    return res.redirect("/change_password_success"); // Redirect to success page
  } catch (error) {
    req.flash("error", error.message);
    return res.render("change_password", {
      title: "Change Password",
      email: email,
      error: req.flash("error"),
    });
  }
}

module.exports = change_password;
