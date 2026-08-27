import { afterEach } from 'vitest';

afterEach(() => {
  document.body.innerHTML = '';
  localStorage.clear();
});
