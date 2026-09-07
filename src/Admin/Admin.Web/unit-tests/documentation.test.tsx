import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { adminGuide, type GuideSection } from '../src/i18n/adminGuide.en';
import { DocumentationPage } from '../src/features/documentation/DocumentationPage';

describe('Admin guide contract', () => {
  it('covers every current application route and keeps fragment identifiers unique', () => {
    const app = readFileSync('src/app/App.tsx', 'utf8');
    const routes = [...app.matchAll(/<Route\s+(?:exact\s+)?path="([^"]+)"/g)].map(match => match[1]);
    const sections: readonly GuideSection[] = adminGuide.sections;
    expect(sections.flatMap(section => section.route ? [section.route] : []).sort())
      .toEqual(routes.filter(route => route !== '/documentation').sort());
    const ids = sections.flatMap(section => [section.id, ...section.topics.map(topic => topic.id)]);
    expect(new Set(ids).size).toBe(ids.length);
    expect(sections.find(section => section.id === 'session')).toBeDefined();
  });

  it('renders the entire searchable guide with valid local anchors and explicit English content', () => {
    const { container } = render(<MemoryRouter><DocumentationPage /></MemoryRouter>);
    const article = screen.getByRole('article');
    expect(article).toHaveAttribute('lang', 'en');
    expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(adminGuide.sections.reduce((count, section) => count + section.topics.length, 0));
    for (const link of container.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')) {
      const target = container.querySelector(`[id="${link.hash.slice(1)}"]`);
      expect(target, link.hash).not.toBeNull();
      expect(target).toHaveAttribute('tabindex', '-1');
    }
    expect(article.textContent).toContain('configuration-resolution check');
    expect(article.textContent).toContain('Five actions across three roles');
    expect(container.querySelectorAll('iframe, script, img')).toHaveLength(0);
    cleanup();
  });
});
