import { useTranslation } from 'react-i18next';
import { DashboardPage } from '../dashboard/DashboardPage';
import { PageTitle } from '../../components/PageTitle';
export function HealthPage() { const { t } = useTranslation(); return <><PageTitle title={t('health')} description={t('healthDescription')} /><DashboardPage /></>; }
