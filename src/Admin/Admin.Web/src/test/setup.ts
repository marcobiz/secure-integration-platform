import '@testing-library/jest-dom/vitest';
import '../i18n';
Object.defineProperty(window, 'matchMedia', { writable: true, value: () => ({ matches: false, addEventListener: () => undefined, removeEventListener: () => undefined }) });
