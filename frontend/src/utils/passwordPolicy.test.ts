import { describe, expect, it } from 'vitest'
import { validatePasswordLocally } from './passwordPolicy'

describe('validatePasswordLocally', () => {
  it('accepts a password that meets every rule', () => {
    expect(validatePasswordLocally('Correct-Horse-9')).toBeNull()
  })

  it('rejects a password shorter than 12 characters', () => {
    expect(validatePasswordLocally('Short-Pw-1')).not.toBeNull()
  })

  it('rejects a password with no digit', () => {
    expect(validatePasswordLocally('NoDigitsHere-ok')).not.toBeNull()
  })

  it('rejects a password with no uppercase letter', () => {
    expect(validatePasswordLocally('lowercase-only-9')).not.toBeNull()
  })
})
