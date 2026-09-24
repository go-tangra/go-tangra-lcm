import { expect, test } from '@playwright/test'
import { goto, signIn } from './helpers'

const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''

test.skip(!password, 'set E2E_OPERATOR_PASSWORD to run the lcm e2e suite')

test('the permissions manager lists certificates and issuers to share', async ({ page }) => {
  await signIn(page, email, password)
  await goto(page, '/lcm/permissions', 'perm-certificates')
  await expect(page.getByTestId('perm-certificates')).toBeVisible()
  await expect(page.getByTestId('perm-issuers')).toBeVisible()
})
