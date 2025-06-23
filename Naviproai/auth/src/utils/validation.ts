export const validatePassword = (password: string): string | null => {
  const minLength = 8; // Minimum password length (you had 6, 8 is a common minimum)

  if (password.length < minLength) {
    return `Password must be at least ${minLength} characters long.`;
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter.';
  }
  if (!/\d/.test(password)) {
    return 'Password must contain at least one number.';
  }
  // Matches common symbols. You can adjust this regex as needed.
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(password)) {
    return 'Password must contain at least one symbol (e.g., !@#$%^&*).';
  }

  return null; // Password is valid
};