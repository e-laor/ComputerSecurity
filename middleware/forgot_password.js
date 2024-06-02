

async function forgot_password (req, res, next) {
    try {
        const { email } = req.body;
        if (!email) {
          throw new Error("Email is required");
        }
    
        const user = await User.findOne({ where: { email: email } });
        if (!user) {
          throw new Error("User with this email does not exist");
        }
    
        if (user.isLocked) {
          throw new Error("This User is locked");
        }
    
        req.session.userEmail = email;
        const token = generateToken();
    
        user.resetPasswordToken = token;
    
        const msg = {
          to: email,
          from: process.env.EMAIL_USER,
          subject: "Password Reset Request",
          text: `Your password reset token is: ${token}`,
        };
    
        await user.save();
    
        sgMail
          .send(msg)
          .then(() => {
            req.flash("success", "An email has been sent with a token.");
            req.session.allowAccess = true; // Set session variable to allow access
            res.redirect(`/token?email=${email}`); // Redirect to the token route after successfully sending the email
          })
          .catch((error) => {
            console.error("Error sending email:", error);
            req.flash("error", "Failed to send email. Please try again later.");
            res.redirect("/forgot-password");
          });
      } catch (error) {
        req.flash("error", error.message); // Display error for wrong email
        res.redirect("/forgot-password");
      }
}

module.exports = forgot_password;