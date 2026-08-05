import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DataTable } from './components/DataTable';
import { PageTitle } from './components/PageTitle';

describe('M5 accessibility primitives', () => {
  it('exposes a single page heading', () => { render(<PageTitle title="Dashboard" description="Status" />); expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Dashboard'); });
  it('gives data tables an accessible name', () => { render(<DataTable rows={[{ code: 'one' }]} label="Resources" columns={[{ key: 'code', label: 'Code', render: row => row.code }]} />); expect(screen.getByRole('table', { name: 'Resources' })).toBeInTheDocument(); });
});
