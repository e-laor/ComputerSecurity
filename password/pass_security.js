// check password stregnth and return true/false with a message
const isPasswordStrong = (password) => {
  const minLength = 10;

  if (password.length < minLength) {
    return { isValid: false, message: "Password must be 10 characters long" };
  }

  const passwordComplexity =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;

  // check password complexity
  if (!passwordComplexity.test(password)) {
    return {
      isValid: false,
      message:
        "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character",
    };
  }

  // if all checks are valid return success
  return { isValid: true, message: "success" };
};

module.exports = {
  isPasswordStrong
};
