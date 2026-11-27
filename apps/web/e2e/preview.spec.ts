import { expect, test } from '@playwright/test';

/** Phase 3 exit criterion: the preview loads no remote resources (invariant 5). */
test('the sanitized preview makes no request for message-supplied resources', async ({ page }) => {
  const requests: string[] = [];
  page.context().on('request', (request) => requests.push(request.url()));

  await page.goto('/preview-harness.html');
  const frame = page.frameLocator('iframe[title="Sanitized message preview"]');
  await expect(frame.getByText('Hello')).toBeVisible();

  // A link click must not navigate the frame either.
  await frame.getByText('Click me').click();
  await page.waitForTimeout(500);

  const leaked = requests.filter(
    (url) => url.includes('__tracker') || url.includes('tracker.example'),
  );
  expect(leaked).toEqual([]);
});
