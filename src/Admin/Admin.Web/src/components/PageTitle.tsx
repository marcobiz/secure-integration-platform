import { Box, Typography } from '@mui/material';
import type { ReactNode } from 'react';
export function PageTitle({ title, description, action }: { title: string; description?: string; action?: ReactNode }) { return <Box sx={{ display: 'flex', alignItems: 'start', justifyContent: 'space-between', gap: 2, mb: 3 }}><Box><Typography variant="h1">{title}</Typography>{description && <Typography color="text.secondary" sx={{ mt: 0.5 }}>{description}</Typography>}</Box>{action}</Box>; }
