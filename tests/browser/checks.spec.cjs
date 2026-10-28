/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

async function login(page, name = 'owner') {
  await page.goto('/');
  await page.locator('#hubLoginMode').click();
  await expect(page.locator('#hubLoginMode')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#hubUrl').fill('http://127.0.0.1:8900');
  await page.locator('#username').fill(name);
  await page.locator('#password').fill(`fixture-${name}-passphrase`);
  await page.locator('#loginButton').click();
  await expect(page.locator('#appView')).toBeVisible();
  await expect(page.locator('#checksList')).toContainText('Fixture HTTPS');
}

test('checks forms, history and TLS warning work on phone and desktop', async ({ page }, info) => {
  await login(page);
  const fixture = page.locator('.check-row').filter({ has: page.getByRole('heading', { name: 'Fixture HTTPS', exact: true }) });
  await expect(fixture).toContainText('HTTP 200');
  await expect(fixture.locator('.check-tls-warning')).toContainText('Требуется обновление сертификата');
  await fixture.locator('summary').click();
  await expect(fixture.locator('.check-history')).toContainText('HTTP 200');
  await page.locator('#checksReload').click();
  await expect(fixture.locator('details')).toHaveAttribute('open', '');
  await expect(fixture.locator('.check-history')).toContainText('HTTP 200');

  const name = `TCP ${info.project.name}`;
  await page.locator('#checksAdd').click();
  await page.locator('#checkName').fill(name);
  await page.locator('#checkUrl').fill('not-a-url');
  await page.locator('#checkKind').selectOption('tcp');
  await expect(page.locator('#checkUrl')).toBeDisabled();
  await expect(page.locator('#checkUrlField')).not.toBeVisible();
  await page.locator('#checkHost').fill('127.0.0.1');
  await page.locator('#checkPort').fill('22');
  await page.locator('#checkConfirm').click();
  await expect(page.locator('#checkDialog')).not.toBeVisible();
  const row = page.locator('.check-row').filter({ has: page.getByRole('heading', { name, exact: true }) });
  await expect(row).toContainText('Ожидаем Agent');
  await row.getByRole('button', { name: `Проверить сейчас: ${name}`, exact: true }).click();
  await expect(page.locator('#checksMessage')).toContainText('Запуск запрошен');
  await row.getByRole('button', { name: `Изменить: ${name}`, exact: true }).click();
  await expect(page.locator('#checkHost')).toHaveValue('127.0.0.1');
  await page.locator('#checkPort').fill('70000');
  await page.locator('#checkKind').selectOption('http');
  await expect(page.locator('#checkPort')).toBeDisabled();
  await page.locator('#checkUrl').fill('https://fixture.invalid/changed');
  await page.locator('#checkEnabled').uncheck();
  await page.locator('#checkConfirm').click();
  await expect(page.locator('#checkDialog')).not.toBeVisible();
  await expect(row).toContainText('Выключена');
  await expect(row.getByRole('button', { name: `Проверить сейчас: ${name}`, exact: true })).toBeDisabled();

  const dnsName = `DNS ${info.project.name}`;
  await page.locator('#checksAdd').click();
  await page.locator('#checkName').fill(dnsName);
  await page.locator('#checkKind').selectOption('dns');
  await expect(page.locator('#checkDnsFields')).toBeVisible();
  await page.locator('#checkDnsHost').fill('example.test');
  await page.locator('#checkRecordType').selectOption('A');
  await page.locator('#checkExpectedIp').fill('203.0.113.7');
  await page.locator('#checkConfirm').click();
  const dnsRow = page.locator('.check-row').filter({ has: page.getByRole('heading', { name: dnsName, exact: true }) });
  await expect(dnsRow).toContainText('DNS');
  await expect(dnsRow).toContainText('Ожидаем Agent');
  await dnsRow.getByRole('button', { name: `Изменить: ${dnsName}`, exact: true }).click();
  await expect(page.locator('#checkDnsHost')).toHaveValue('example.test');
  await expect(page.locator('#checkExpectedIp')).toHaveValue('203.0.113.7');
  await page.locator('#checkCancel').click();

  for (const theme of ['light', 'dark']) {
    await page.locator('#topThemeSelect').selectOption(theme);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.locator('#checksHeading').evaluate((el) => el.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: info.outputPath(`checks-${theme}-viewport.png`) });
  }
  await row.getByRole('button', { name: `Удалить: ${name}`, exact: true }).click();
  await expect(page.locator('#checkDialogTarget')).toContainText('История этой проверки будет удалена');
  await page.locator('#checkConfirm').click();
  await expect(row).toHaveCount(0);
  await page.locator('#logoutButton').click();
  await login(page, 'reader');
  await expect(page.locator('#checksAdd')).not.toBeVisible();
  await expect(page.locator('.checks-list button')).toHaveCount(0);
  await fixture.locator('summary').click();
  await expect(fixture.locator('.check-history')).toContainText('HTTP 200');
  await expect(page.locator('#checksList')).not.toContainText('fixture.invalid');
  await expect(page.locator('#checksList')).not.toContainText('example.test');
  await expect(page.locator('#checksList')).not.toContainText('203.0.113.7');
});
