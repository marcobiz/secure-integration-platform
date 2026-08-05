import { lazy, Suspense } from 'react';
import { BrowserRouter, Route, Switch } from 'react-router-dom';
import { SessionProvider } from '../auth/SessionContext'; import { LoginPage } from '../auth/LoginPage'; import { LoadingState } from '../components/AsyncState'; import { AdminLayout } from '../layouts/AdminLayout';
import { DirtyStateProvider } from '../navigation/DirtyStateContext';
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
const Access = lazy(() => import('../features/security/AccessPage').then(value => ({ default: value.AccessPage })));

function CurrentPage() { return <Switch><Route exact path="/" component={Dashboard} /><Route path="/tenants" component={Tenants} /><Route path="/applications" component={Applications} /><Route path="/installations" component={Installations} /><Route path="/connectors" component={Connectors} /><Route path="/bindings" component={Bindings} /><Route path="/grants" component={Grants} /><Route path="/approvals" component={Approvals} /><Route path="/access" component={Access} /><Route path="/audit" render={() => <TenantData kind="audit" />} /><Route path="/health" component={Health} /><Route component={Dashboard} /></Switch>; }
export function App() { return <BrowserRouter basename="/admin"><DirtyStateProvider><SessionProvider fallback={<LoginPage />}><Suspense fallback={<LoadingState />}><AdminLayout><CurrentPage /></AdminLayout></Suspense></SessionProvider></DirtyStateProvider></BrowserRouter>; }
