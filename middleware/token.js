
async function token (req, res, next) {

try {
    const { token, email } = req.body; // Ensure email is extracted from req.body
    if (!token) {
      req.flash("error", "Token is required");
      return res.render("token", {
        title: "Token",
        email: email,
        error: req.flash("error"),
        success: req.flash("success"),
      });
    }

    const user = await User.findOne({ where: { email: email } });
    if (!user) {
      req.flash("error", "User not found");
      return res.render("token", {
        title: "Token",
        email: email,
        error: req.flash("error"),
        success: req.flash("success"),
      });
    }

    if (token !== user.resetPasswordToken) {
      req.flash("error", "Token is invalid");
      return res.render("token", {
        title: "Token",
        email: email,
        error: req.flash("error"),
        success: req.flash("success"),
      });
    }

    req.flash("success", "Token verified successfully.");
    req.session.allowAccess = true; // Set session variable to allow access
    return res.render("change_password", {
      title: "Reset Password",
      email: email,
      error: req.flash("error"),
      success: req.flash("success"),
    });
  } catch (error) {
    req.flash("error", error.message);
    return res.render("token", {
      title: "Token",
      email: req.body.email,
      error: req.flash("error"),
      success: req.flash("success"),
    });
  }
}

module.exports = token;