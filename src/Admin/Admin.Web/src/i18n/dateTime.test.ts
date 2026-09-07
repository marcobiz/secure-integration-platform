import { describe, expect, it } from 'vitest';
import { formatDate, formatDateTime } from './dateTime';

describe('technical date display', () => {
  it('uses an unambiguous English month, padded day and year', () => {
    expect(formatDate('2026-09-07T13:04:05Z')).toBe('07 Sep 2026');
    expect(formatDate('2026-11-07T13:04:05Z')).toBe('07 Nov 2026');
  });

  it('includes explicit UTC and 24-hour time without changing the source value', () => {
    const source = '2026-09-07T01:04:05+02:00';
    expect(formatDateTime(source)).toBe('06 Sep 2026, 23:04:05 UTC');
    expect(source).toBe('2026-09-07T01:04:05+02:00');
    expect(formatDateTime('2026-09-07T00:00:00Z')).toBe('07 Sep 2026, 00:00:00 UTC');
  });

  it('does not break a page when optional metadata is missing or invalid', () => {
    for (const value of [null, undefined, '', 'not-a-date']) {
      expect(formatDate(value)).toBe('—');
      expect(formatDateTime(value)).toBe('—');
    }
  });
});
