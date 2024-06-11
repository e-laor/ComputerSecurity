// Dictionary words array
const dictionaryWords = [
  "password", "123456", "qwerty", "letmein", "welcome","hello","world"
  // Add more words as needed
];

// Function to replace common character substitutions
const normalizePassword = (password) => {
  return password.replace(/@/g, 'a')
                 .replace(/!/g, 'i')
                 .replace(/0/g, 'o')
                 .replace(/3/g, 'e')
                 .replace(/\$/g, 's');
};

// Check password strength and return true/false with a message
const isPasswordStrong = (password) => {
  const exactLength = 10;

  // Check the length
  if (password.length !== exactLength) {
    return { isValid: false, message: "Password must be exactly 10 characters long" };
  }

  // Check for at least one lowercase letter, one uppercase letter, and one number
  const passwordComplexity = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{10}$/;

  if (!passwordComplexity.test(password)) {
    return {
      isValid: false,
      message: "Password must contain at least one lowercase letter, one uppercase letter, and one number"
    };
  }

  // Normalize password to account for common substitutions
  const normalizedPassword = normalizePassword(password);

  // Check if the normalized password contains any dictionary words
  for (const word of dictionaryWords) {
    if (normalizedPassword.toLowerCase().includes(word.toLowerCase())) {
      return {
        isValid: false,
        message: "Password must not contain dictionary words"
      };
    }
  }

  // If all checks are valid, return success
  return { isValid: true, message: "Success" };
};

// Example usage
const password = "P@ssword11";
const result = isPasswordStrong(password);
console.log(result);  // Should return that the password is not valid

module.exports = {
  isPasswordStrong
};
