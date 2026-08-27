import { expect, test } from 'vitest';

test('happy-dom creates uppercase button tag names', () => {
  expect(document.createElement('button').tagName).toBe('BUTTON');
});
