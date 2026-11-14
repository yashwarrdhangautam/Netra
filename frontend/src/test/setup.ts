import { afterAll, afterEach, beforeAll } from 'vitest'
import { server } from './server'

// Unhandled requests fail the test, so a missing mock shows up instead of hitting the network.
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
