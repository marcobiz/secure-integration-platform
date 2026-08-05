import { lazy, Suspense } from 'react';
import { SessionProvider } from '../auth/SessionContext'; import { LoginPage } from '../auth/LoginPage'; import { LoadingState } from '../components/AsyncState'; import { AdminLayout } from '../layouts/AdminLayout';
const Dashboard = lazy(() => import('../features/dashboard/DashboardPage').then(value => ({ default: value.DashboardPage })));
const Tenants = lazy(() => import('../features/resources/TenantsPage').then(value => ({ default: value.TenantsPage })));
const Applications = lazy(() => import('../features/resources/ApplicationsPage').then(value => ({ default: value.ApplicationsPage })));
const Installations = lazy(() => import('../features/resources/InstallationsPage').then(value => ({ default: value.InstallationsPage })));
const Connectors = lazy(() => import('../features/connectors/ConnectorsPage').then(value => ({ default: value.ConnectorsPage })));
const Bindings = lazy(() => import('../features/integration/BindingsPage').then(value => ({ default: value.BindingsPage })));
const Approvals = lazy(() => import('../features/integration/ApprovalsPage').then(value => ({ default: value.ApprovalsPage })));
const Grants = lazy(() => import('../features/integration/GrantsPage').then(value => ({ default: value.GrantsPage })));
const TenantData = lazy(() => import('../features/operations/TenantDataPage').then(value => ({ default: value.TenantDataPage })));
const Health = lazy(() => import('../features/operations/HealthPage').then(value => ({ default: value.HealthPage })));

function CurrentPage() { const path = window.location.pathname.replace(/^\/admin\/?/, ''); switch (path) { case 'tenants': return <Tenants />; case 'applications': return <Applications />; case 'installations': return <Installations />; case 'connectors': return <Connectors />; case 'bindings': return <Bindings />; case 'grants': return <Grants />; case 'approvals': return <Approvals />; case 'audit': return <TenantData kind="audit" />; case 'health': return <Health />; default: return <Dashboard />; } }
export function App() { return <SessionProvider fallback={<LoginPage />}><Suspense fallback={<LoadingState />}><AdminLayout><CurrentPage /></AdminLayout></Suspense></SessionProvider>; }
