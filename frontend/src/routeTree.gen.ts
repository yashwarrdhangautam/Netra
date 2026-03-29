import { createRootRoute, createRoute, createRouter, Outlet } from '@tanstack/react-router'
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

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
})

export const routeTree = rootRoute.addChildren([
  indexRoute,
  scansRoute,
  scanDetailRoute,
  findingsRoute,
  findingDetailRoute,
  reportsRoute,
  complianceRoute,
  targetsRoute,
  attackGraphRoute,
  settingsRoute,
  loginRoute,
])
