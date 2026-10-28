/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const { test, expect } = require('@playwright/test');

async function login(page, name = 'owner', password = `fixture-${name}-passphrase`) {
  await page.goto('/');
  await page.locator('#hubLoginMode').click();
  await expect(page.locator('#hubLoginMode')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#hubUrl').fill('http://127.0.0.1:8900');
  await page.locator('#username').fill(name);
  await page.locator('#password').fill(password);
  await page.locator('#loginButton').click();
  await expect(page.locator('#appView')).toBeVisible();
  await expect(page.locator('#sessionIdentity')).toContainText(name);
}

async function settings(page) {
  await page.locator('[data-view="settings"]').click();
  await expect(page.locator('#settingsView')).toBeVisible();
}

async function noOverflow(page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
}

test('administrator manages accounts through real forms and protects the last administrator', async ({ page }, testInfo) => {
  await login(page);
  await settings(page);
  await expect(page.locator('#usersAdd')).toBeEnabled();
  const name = `browser-${testInfo.project.name}`;
  await page.locator('#usersAdd').click();
  await page.locator('#userUsername').fill(name);
  await expect(page.locator('#userRole')).toHaveValue('viewer');
  await page.locator('#userGeneratePassword').click();
  await expect(page.locator('#userPassword')).toHaveAttribute('type', 'text');
  await page.locator('#userDialogConfirm').click();
  await expect(page.locator('#userDialogError')).toContainText('Сохраните сгенерированный пароль');
  await expect(page.locator('#userDialog')).toBeVisible();
  await page.locator('#userPasswordSaved').check();
  await page.locator('#userDialogConfirm').click();
  await expect(page.locator('#userDialog')).not.toBeVisible();
  const row = page.locator('.user-row').filter({ has: page.getByRole('heading', { name, exact: true }) });
  await expect(row).toContainText('Наблюдатель');
  await row.getByRole('button', { name: `Изменить доступ: ${name}`, exact: true }).click();
  await page.locator('#userRole').selectOption('operator');
  await page.locator('#userDialogConfirm').click();
  await expect(page.locator('#userDialog')).not.toBeVisible();
  await expect(row).toContainText('Оператор');
  for (const theme of ['light', 'dark']) {
    await page.locator('#settingsThemeSelect').selectOption(theme);
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    await noOverflow(page);
    const colors = await page.locator('#usersMessage').evaluate((element) => {
      const probe = document.createElement('span'); probe.style.color = 'var(--sg-accent)';
      document.body.append(probe);
      const colors = [getComputedStyle(element).color, getComputedStyle(probe).color];
      probe.remove(); return colors;
    });
    expect(colors[0]).toBe(colors[1]);
    await page.locator('#usersHeading').scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`accounts-${theme}.png`), fullPage: true });
    await page.locator('#usersHeading').evaluate((element) => element.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: testInfo.outputPath(`accounts-${theme}-viewport.png`) });
  }
  await row.getByRole('button', { name: `Новый пароль: ${name}`, exact: true }).click();
  const password = 'browser-reset-passphrase';
  await page.locator('#userPassword').fill(password);
  await page.locator('#userDialogConfirm').click();
  await expect(page.locator('#userDialog')).not.toBeVisible();
  await page.locator('#logoutButton').click();
  await login(page, name, password);
  await expect(page.locator('#sessionIdentity')).toContainText('Оператор');
  await expect(page.locator('[data-view="commands"]')).not.toBeVisible();
  await page.locator('#logoutButton').click();
  await login(page);
  await settings(page);
  await row.getByRole('button', { name: `Удалить: ${name}`, exact: true }).click();
  await page.locator('#userDialogConfirm').click();
  await expect(page.locator('#userDialog')).not.toBeVisible();
  await expect(row).toHaveCount(0);
  const owner = page.locator('.user-row').filter({ has: page.getByRole('heading', { name: 'owner', exact: true }) });
  await owner.getByRole('button', { name: 'Изменить доступ: owner', exact: true }).click();
  await page.locator('#userEnabled').uncheck();
  await page.locator('#userDialogConfirm').click();
  await expect(page.locator('#userDialogError')).toContainText('последний действующий администратор');
  await page.locator('#userDialogCancel').click();
  await expect(page.locator('#sessionIdentity')).toContainText('owner');
});

test('viewer sees monitoring and own settings without administrator controls', async ({ page }, testInfo) => {
  await login(page, 'reader');
  await expect(page.locator('#accessNotice')).toContainText('наблюдателя');
  for (const view of ['commands', 'journal', 'files', 'telegram', 'audit', 'start']) {
    await expect(page.locator(`[data-view="${view}"]`)).not.toBeVisible();
  }
  await page.locator('[data-view="incidents"]').click();
  await expect(page.locator('#eventsList')).toContainText('Высокая нагрузка CPU');
  await expect(page.locator('#eventsList').getByRole('button', { name: 'Подтвердить', exact: true })).toHaveCount(0);
  await settings(page);
  await expect(page.locator('#usersHeading')).not.toBeVisible();
  await expect(page.locator('#monitoringCpu')).toBeDisabled();
  await expect(page.locator('#monitoringSave')).not.toBeVisible();
  await expect(page.locator('#changePasswordButton')).toBeVisible();
  await page.locator('#settingsThemeSelect').selectOption('light');
  await noOverflow(page);
  await page.screenshot({ path: testInfo.outputPath('viewer-settings.png'), fullPage: true });
});

test('operator can acknowledge incidents while privileged views stay hidden', async ({ page }) => {
  await login(page, 'operator');
  await expect(page.locator('#sessionIdentity')).toContainText('Оператор');
  await page.locator('[data-view="incidents"]').click();
  await expect(page.locator('#eventsList').getByRole('button', { name: 'Подтвердить', exact: true })).toBeVisible();
  await expect(page.locator('[data-view="commands"]')).not.toBeVisible();
  await expect(page.locator('#addServerButton')).not.toBeVisible();
});
