import { createRootRoute, createRoute, Navigate, Outlet, useLocation } from '@tanstack/react-router'
import { Layout } from '@/components/layout/Layout'
import { useAuthStore } from '@/stores/authStore'
import { Dashboard } from '@/pages/Dashboard'
import { ScansList } from '@/pages/ScansList'
import { ScanDetail } from '@/pages/ScanDetail'
import { FindingsList } from '@/pages/FindingsList'
import { FindingDetail } from '@/pages/FindingDetail'
import { Reports } from '@/pages/Reports'
import { Compliance } from '@/pages/Compliance'
import { Targets } from '@/pages/Targets'
import { AttackGraph } from '@/pages/AttackGraph'
import { Settings } from '@/pages/Settings'
import { Login } from '@/pages/Login'
import { Users } from '@/pages/Users'
import { ScanCompare } from '@/pages/ScanCompare'
import { BBConsole } from '@/pages/bb/BBConsole'
import { BBPrograms } from '@/pages/bb/BBPrograms'
import { BBScope } from '@/pages/bb/BBScope'
import { BBHunts } from '@/pages/bb/BBHunts'
import { BBTriage } from '@/pages/bb/BBTriage'
import { BBSubmissions } from '@/pages/bb/BBSubmissions'
import { BBAudit } from '@/pages/bb/BBAudit'
import { BBDoctor } from '@/pages/bb/BBDoctor'
import { BBFindingLab } from '@/pages/bb/BBFindingLab'
import { BBGraph } from '@/pages/bb/BBGraph'
import { BBSubmissionDetail } from '@/pages/bb/BBSubmissionDetail'
import { BBHuntDetail } from '@/pages/bb/BBHuntDetail'
import { BBSettings } from '@/pages/bb/BBSettings'
import { Schedules } from '@/pages/Schedules'
import { parseFindingSearch } from '@/utils/findingSearch'
import { Audit } from '@/pages/Audit'
import { ResetPassword } from '@/pages/ResetPassword'

// Every page except /login needs a signed-in user. The login page is shown
// without the sidebar layout.
function RootGate() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)
  const { pathname } = useLocation()

  // Sign-in and the emailed password-reset page are shown without the sidebar layout.
  if (pathname === '/login' || pathname === '/reset-password') {
    return <Outlet />
  }
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  return (
    <Layout>
      <Outlet />
    </Layout>
  )
}

const rootRoute = createRootRoute({
  component: RootGate,
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: Dashboard,
})

const scansRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans',
  component: ScansList,
})

const scanDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans/$scanId',
  component: ScanDetail,
})

const findingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings',
  component: FindingsList,
  // Filters live in the URL so a scan's findings view survives navigation and can be shared.
  validateSearch: parseFindingSearch,
})

const findingDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings/$findingId',
  component: FindingDetail,
  validateSearch: parseFindingSearch,
})

const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports',
  component: Reports,
  validateSearch: (search: Record<string, unknown>): { scan_id?: string } => ({
    scan_id: typeof search.scan_id === 'string' ? search.scan_id : undefined,
  }),
})

const complianceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/compliance',
  component: Compliance,
})

const targetsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/targets',
  component: Targets,
})

const attackGraphRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/attack-graph',
  component: AttackGraph,
})

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/settings',
  component: Settings,
})

const usersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/users',
  component: Users,
})

const scanCompareRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/scans/compare',
  component: ScanCompare,
})

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
})

const resetPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reset-password',
  component: ResetPassword,
})

const bbRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb',
  component: BBConsole,
})

const bbProgramsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/programs',
  component: BBPrograms,
})

const bbScopeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/scope',
  component: BBScope,
})

const bbHuntsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/hunts',
  component: BBHunts,
})

const bbHuntDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/hunts/$huntId',
  component: BBHuntDetail,
})

const bbSettingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/settings',
  component: BBSettings,
})

const schedulesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/schedules',
  component: Schedules,
})

const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/audit',
  component: Audit,
})

const bbTriageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/triage',
  component: BBTriage,
})

const bbSubmissionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/submissions',
  component: BBSubmissions,
})

const bbSubmissionDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/submissions/$submissionId',
  component: BBSubmissionDetail,
})

const bbAuditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/audit',
  component: BBAudit,
})

const bbDoctorRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/doctor',
  component: BBDoctor,
})

const bbFindingLabRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/findings/$findingId',
  component: BBFindingLab,
})

const bbGraphRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/bb/graph',
  component: BBGraph,
})

export const routeTree = rootRoute.addChildren([
  indexRoute,
  scansRoute,
  scanDetailRoute,
  scanCompareRoute,
  findingsRoute,
  findingDetailRoute,
  reportsRoute,
  complianceRoute,
  targetsRoute,
  attackGraphRoute,
  settingsRoute,
  usersRoute,
  loginRoute,
  resetPasswordRoute,
  bbRoute,
  bbProgramsRoute,
  bbScopeRoute,
  bbHuntsRoute,
  bbHuntDetailRoute,
  bbSettingsRoute,
  schedulesRoute,
  auditRoute,
  bbTriageRoute,
  bbSubmissionsRoute,
  bbSubmissionDetailRoute,
  bbAuditRoute,
  bbDoctorRoute,
  bbFindingLabRoute,
  bbGraphRoute,
])
