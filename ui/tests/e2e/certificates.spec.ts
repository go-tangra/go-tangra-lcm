import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { goto, signIn } from './helpers'

// Runs through the platform shell/gateway; the remote only exists inside the
// shell. Set E2E_OPERATOR_PASSWORD to run it (mirrors the notification suite).
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''

test.skip(!password, 'set E2E_OPERATOR_PASSWORD to run the lcm e2e suite')

test('create a self-signed issuer, then issue a certificate against it', async ({ page }) => {
  await signIn(page, email, password)

  // Issuer.
  await goto(page, '/lcm/issuers', 'issuer-new')
  await page.getByTestId('issuer-new').click()
  await page.getByTestId('issuer-name').locator('input').fill('E2E root')
  await page.getByTestId('issuer-trust-domain').locator('input').fill('example.org')
  await page.getByTestId('issuer-save').click()
  await expect(page.getByTestId('issuer-drawer')).not.toBeVisible()
  await expect(page.getByText('E2E root')).toBeVisible()

  // Certificate.
  await goto(page, '/lcm/certificates', 'cert-issue-open')
  await page.getByTestId('cert-issue-open').click()
  await page.getByTestId('issue-spiffe').locator('input').fill('spiffe://example.org/service/e2e')
  await page.getByTestId('issue-submit').click()
  await expect(page.getByTestId('issue-result')).toBeVisible({ timeout: 30_000 })
  await page.getByTestId('issue-done').click()
  await expect(page.getByText('spiffe://example.org/service/e2e')).toBeVisible()

  const results = await new AxeBuilder({ page }).analyze()
  expect(results.violations.filter((v) => v.impact === 'critical')).toEqual([])
})

test('the dashboard shows statistics cards', async ({ page }) => {
  await signIn(page, email, password)
  await goto(page, '/lcm', 'stats-card')
  await expect(page.getByTestId('stat-certificates')).toBeVisible()
  await expect(page.getByTestId('stat-issuers')).toBeVisible()
})
