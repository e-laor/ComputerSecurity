const fs = require('fs');

// Load dictionary words from a file into a list
const dictionaryWords = fs.readFileSync('./security/passwords.txt', 'utf-8').split('\n');

// Function to replace common character substitutions
const normalizePassword = (password) => {
  return password.replace(/@/g, 'a')
                 .replace(/!/g, 'i')
                 .replace(/0/g, 'o')
                 .replace(/3/g, 'e')
                 .replace(/\$/g, 's');
};

// Check password strength and return true/false with a message
const isPasswordStrong = (password, username) => {
  const minLength = 10;

  // Check the length
  if (password.length < minLength) {
    return { isValid: false, message: "Password must be at least 10 characters long" };
  }

  // Check for at least one lowercase letter, one uppercase letter, and one number
  const passwordComplexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;

  if (!passwordComplexity.test(password)) {
    return {
      isValid: false,
      message: "Password must contain at least one lowercase letter, one uppercase letter, and one number"
    };
  }
  
  // checks if password contains username
  if (password.toLowerCase().includes(username)) {
    return {
      isValid: false,
      message: "Password cannot contain username.",
    };
  }
  
  // Normalize password to account for common substitutions
  const normalizedPassword = normalizePassword(password);

  // Check if the normalized password contains any dictionary words
  for (const word of dictionaryWords) {
    if (normalizedPassword === word.trim()) {
      return {
        isValid: false,
        message: "Password is too common, please choose a stronger one."
      };
    }
  }

  // If all checks are valid, return success
  return { isValid: true, message: "Success" };
};

// Example usage
const password = "lololoLeO1@!";
const result = isPasswordStrong(password);
console.log(result);  // Should return that the password is not valid

module.exports = {
  isPasswordStrong
};
