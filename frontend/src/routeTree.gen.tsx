import { createRootRoute, createRoute, Outlet } from '@tanstack/react-router'
import { Layout } from '@/components/layout/Layout'
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

const rootRoute = createRootRoute({
  component: () => (
    <Layout>
      <Outlet />
    </Layout>
  ),
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
})

const findingDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings/$findingId',
  component: FindingDetail,
})

const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports',
  component: Reports,
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
  bbRoute,
  bbProgramsRoute,
  bbScopeRoute,
  bbHuntsRoute,
  bbTriageRoute,
  bbSubmissionsRoute,
  bbSubmissionDetailRoute,
  bbAuditRoute,
  bbDoctorRoute,
  bbFindingLabRoute,
  bbGraphRoute,
])
