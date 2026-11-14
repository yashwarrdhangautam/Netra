import { setupServer } from 'msw/node'

// Default handlers are empty. Each test adds the responses it needs with server.use().
export const server = setupServer()
