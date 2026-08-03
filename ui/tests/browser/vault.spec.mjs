// Drives the built vault WASM bundle in a real browser. The Rust tests cannot
// see this: rendering a component tree in a native test does not exercise the
// compiled bundle, its event handlers, or its assets.
import { chromium } from 'playwright';

// The bundle's asset paths are absolute under the gateway's contract path,
// so the harness serves it there rather than at `/`.
const URL = process.env.VAULT_URL;
if (!URL) {
  console.error('VAULT_URL not set -- run via scripts/browser-test.sh');
  process.exit(2);
}
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` -- ${detail}` : ''}`);
}

const browser = await chromium.launch();
const page = await browser.newPage();

const consoleErrors = [];
page.on('console', (m) => {
  // `_dioxus` is the debug build's hot-reload socket; it does not exist in a
  // release bundle and is not something the vault ships.
  if (m.type() === 'error' && !m.text().includes('_dioxus')) consoleErrors.push(m.text());
});
page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message}`));

await page.goto(URL, { waitUntil: 'networkidle' });
await page.waitForSelector('.identity-card', { timeout: 20000 });

// --- The three example identities render ---------------------------------
const cards = await page.locator('.identity-card').count();
check('three example identities render', cards === 3, `got ${cards}`);

// --- The backup nag appears on exactly the un-backed-up ones -------------
// Example data: 3xKm9Rvp is backed_up:true; the other two are false.
const nags = await page.locator('.backup-nag').count();
check('backup nag shows on the two un-backed-up keys only', nags === 2, `got ${nags}`);

const backedUpCard = page.locator('.identity-card', { has: page.locator('code', { hasText: '3xKm9Rvp' }) });
const nagOnBackedUp = await backedUpCard.locator('.backup-nag').count();
check('no nag on the backed-up key', nagOnBackedUp === 0, `got ${nagOnBackedUp}`);

const unbackedCard = page.locator('.identity-card', { has: page.locator('code', { hasText: '7bNq2Wft' }) });
const nagOnUnbacked = await unbackedCard.locator('.backup-nag').count();
check('nag present on an un-backed-up key', nagOnUnbacked === 1, `got ${nagOnUnbacked}`);

// --- The nag is actionable, not just decorative --------------------------
const backupBtn = unbackedCard.locator('button.action-backup');
check('nag carries a Back up button', (await backupBtn.count()) === 1);
check('Back up button is visible', await backupBtn.isVisible());
const btnBox = await backupBtn.boundingBox();
check('Back up button has a real hit area', !!btnBox && btnBox.width > 20 && btnBox.height > 14,
  btnBox ? `${Math.round(btnBox.width)}x${Math.round(btnBox.height)}` : 'no box');

// --- Nag styling reads as a nudge, not an error --------------------------
const nagColor = await unbackedCard.locator('.backup-nag-text').evaluate((el) => getComputedStyle(el).color);
check('nag text uses the warm accent, not the danger red', nagColor === 'rgb(232, 160, 96)', nagColor);

// --- The nag must not push the real actions off the card -----------------
const actionsVisible = await unbackedCard.locator('.card-actions-row button', { hasText: 'Sign' }).isVisible();
check('Sign action still visible under the nag', actionsVisible);

// --- Backing up is two steps: the marker must not be set by a download ---
// A browser gives no signal that a file reached the disk, so clicking "Back up"
// alone must never clear the reminder -- that is the failure that costs the key.
await backupBtn.click();
await page.waitForTimeout(600);
const confirmBtn = unbackedCard.locator('button', { hasText: 'I have the file' });
check('download swaps the nag to an explicit confirmation', (await confirmBtn.count()) === 1);
check('the nag is still showing before confirmation',
  (await unbackedCard.locator('.backup-nag').count()) === 1);
const confirmText = await unbackedCard.locator('.backup-nag-text').innerText();
check('confirmation asks about the file, not the click',
  /have the file|still have/i.test(confirmText), confirmText.slice(0, 60));

// The confirm prompt must belong to the key that was downloaded, and to no
// other. Dioxus reuses component state across re-renders, so a flag that was
// not bound to a fingerprint could offer to mark a different key backed up.
const otherCard = page.locator('.identity-card', { has: page.locator('code', { hasText: 'Hv5sRe8x' }) });
check('the other card is not offering to confirm a file it never downloaded',
  (await otherCard.locator('button', { hasText: 'I have the file' }).count()) === 0);

// Confirming is what clears it -- and only for the key confirmed.
await confirmBtn.click();
await page.waitForTimeout(600);
check('confirming clears that key\'s reminder',
  (await unbackedCard.locator('.backup-nag').count()) === 0);
check('the other un-backed-up key still nags',
  (await page.locator('.backup-nag').count()) === 1);

// --- The half-lost-identity warning renders and reads as serious ---------
const warn = page.locator('.vault-warning');
check('half-lost-identity warning renders', (await warn.count()) === 1);
check('warning names the count', (await warn.innerText()).includes('One identity'));
const warnColor = await warn.locator('strong').evaluate((el) => getComputedStyle(el).color);
check('warning uses danger red, unlike the nag', warnColor === 'rgb(232, 96, 96)', warnColor);
const warnBox = await warn.boundingBox();
const firstCardBox = await page.locator('.identity-card').first().boundingBox();
check('warning sits above the cards, not buried under them',
  !!warnBox && !!firstCardBox && warnBox.y < firstCardBox.y);

// --- Nothing horizontally overflows at a narrow viewport -----------------
await page.setViewportSize({ width: 380, height: 800 });
await page.waitForTimeout(200);
const overflow = await page.evaluate(() =>
  document.documentElement.scrollWidth - document.documentElement.clientWidth);
check('no horizontal overflow at 380px', overflow <= 1, `overflow ${overflow}px`);
// The card used above has been confirmed and no longer nags, so check the
// other un-backed-up one.
const stillNagging = page.locator('.identity-card', { has: page.locator('code', { hasText: 'Hv5sRe8x' }) });
const narrowBtnVisible = await stillNagging.locator('button.action-backup').isVisible();
check('Back up button still reachable at 380px', narrowBtnVisible);
await page.setViewportSize({ width: 1280, height: 900 });

// --- The console must be clean -------------------------------------------
check('browser console has no errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));

if (process.env.VAULT_SCREENSHOT) {
  await page.screenshot({ path: process.env.VAULT_SCREENSHOT, fullPage: true });
}
await browser.close();

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
