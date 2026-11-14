// Mirrors netra.core.passwords.validate_password so the form can explain a rejection early.
export function validatePasswordLocally(password: string): string | null {
  if (password.length < 12) return 'Password must be at least 12 characters.'
  if (password.toLowerCase() === password || password.toUpperCase() === password) {
    return 'Password must mix upper- and lower-case letters.'
  }
  if (!/\d/.test(password)) return 'Password must contain a digit.'
  return null
}
