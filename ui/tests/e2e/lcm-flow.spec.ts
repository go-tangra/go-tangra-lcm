import { expect, test, type Page } from '@playwright/test'
import { base, signIn } from '../../../../gateway/shell/tests/e2e/helpers'

// Quickstart §4 flow for the lcm remote at the three reference widths: issuers,
// certificates (request dialog validation), requests, secrets drawer and the
// ./header certificate badge. Needs a full platform; skips without operator credentials.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const viewports = [{ name: 'phone', width: 320, height: 640 }, { name: 'tablet', width: 768, height: 1024 }, { name: 'desktop', width: 1280, height: 800 }]

async function openNav(page: Page, group: string, entry: string): Promise<void> {
  const burger = page.getByRole('button', { name: 'Open navigation' })
  if (await burger.isVisible()) await burger.click()
  const g = page.getByTestId('nav-group-' + group)
  if ((await g.getAttribute('aria-expanded')) !== 'true') await g.click()
  await page.getByTestId('nav-' + group).filter({ hasText: entry }).first().click()
}

test.describe('lcm remote', () => {
  test.skip(!password, 'E2E_OPERATOR_PASSWORD not set')
  for (const vp of viewports) {
    test(`${vp.name}: header badge, issuers, certificates dialog, requests, secrets`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      const violations: string[] = []
      await page.addInitScript(() => document.addEventListener('securitypolicyviolation', (e) => console.error('CSP:' + (e as SecurityPolicyViolationEvent).violatedDirective)))
      page.on('console', (m) => { if (m.text().startsWith('CSP:')) violations.push(m.text()) })
      await page.goto(base + '/')
      await signIn(page, email, password)
      await expect(page.getByTestId('cert-button')).toBeVisible()
      await page.getByTestId('cert-button').click()
      await expect(page.getByTestId('cert-open')).toBeVisible()
      await page.keyboard.press('Escape')
      await openNav(page, 'lcm', 'Issuers')
      await expect(page.getByTestId('issuers-table')).toBeVisible()
      await openNav(page, 'lcm', 'Certificates')
      await page.getByTestId('cert-issue-open').click()
      await page.getByTestId('issue-spiffe').locator('input').fill('not-a-spiffe-id')
      await page.getByTestId('issue-submit').click()
      await expect(page.getByRole('dialog').getByRole('alert')).toContainText('SPIFFE')
      await page.keyboard.press('Escape')
      await openNav(page, 'lcm', 'Requests')
      await expect(page.getByTestId('requests-table')).toBeVisible()
      await openNav(page, 'lcm', 'Secrets')
      await page.getByTestId('secret-new').click()
      const value = page.getByTestId('secret-value').locator('textarea')
      await value.fill('e2e-secret-value')
      await page.getByTestId('secret-save').click() // name missing → blocked client-side
      await expect(page.locator('aside[role=dialog]').getByRole('alert').first()).toContainText('required')
      await page.keyboard.press('Escape')
      await openNav(page, 'lcm', 'Dashboard')
      await expect(page.getByTestId('stat-certificates')).toBeVisible()
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0)
      expect(await page.locator('main [style]').count()).toBe(0)
      expect(await page.content()).not.toContain('e2e-secret-value')
      expect(violations).toEqual([])
    })
  }
})
