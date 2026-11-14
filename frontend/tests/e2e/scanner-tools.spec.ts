import { test, expect, type Page } from '@playwright/test'

// Settings shows which scanner binaries the worker has. Credentials come from the environment.
//   NETRA_E2E_EMAIL, NETRA_E2E_PASSWORD  (an existing admin account)

const EMAIL = process.env.NETRA_E2E_EMAIL ?? ''
const PASSWORD = process.env.NETRA_E2E_PASSWORD ?? ''

async function signIn(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(EMAIL)
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login$/, { timeout: 15_000 })
}

test.describe('Scanner tools card', () => {
  test.skip(!EMAIL || !PASSWORD, 'Set NETRA_E2E_EMAIL and NETRA_E2E_PASSWORD to run')

  test('settings lists scanner tools with an install state', async ({ page }) => {
    await signIn(page)
    await page.goto('/settings')
    await page.getByRole('tab', { name: 'Integrations' }).click()
    const card = page.getByText('Scanner tools').first()
    await expect(card).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText(/All required tools are installed|required tool\(s\) missing/)).toBeVisible()
    await expect(page.getByText('nikto', { exact: false }).first()).toBeVisible()
  })
})
