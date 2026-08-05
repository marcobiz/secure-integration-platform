import { Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import type { ReactNode } from 'react';
import { EmptyState } from './AsyncState';

export interface Column<T> { key: string; label: string; render: (row: T) => ReactNode; }
export function DataTable<T>({ rows, columns, label }: { rows: T[]; columns: Column<T>[]; label: string }) {
  if (rows.length === 0) return <EmptyState />;
  return <TableContainer component={Paper}><Table size="small" aria-label={label}><TableHead><TableRow>{columns.map(column => <TableCell key={column.key} scope="col">{column.label}</TableCell>)}</TableRow></TableHead><TableBody>{rows.map((row, index) => <TableRow key={index}>{columns.map(column => <TableCell key={column.key}>{column.render(row)}</TableCell>)}</TableRow>)}</TableBody></Table></TableContainer>;
}
