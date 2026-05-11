import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { Button } from '@/components/ui/Button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/Table'
import { Badge } from '@/components/ui/Badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { useAuthStore, type User } from '@/stores/authStore'
import { UserPlus, Trash2, Shield, UserCheck, UserX } from 'lucide-react'

export function Users() {
  const { user: currentUser, isAdmin } = useAuthStore()
  const queryClient = useQueryClient()
  const API_BASE = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000'

  // Get auth header
  const getAuthHeaders = () => {
    const token = localStorage.getItem('netra_token')
    return {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    }
  }

  // Fetch users
  const { data: users = [], isLoading } = useQuery<User[]>({
    queryKey: ['users'],
    queryFn: async () => {
      const response = await axios.get(`${API_BASE}/api/v1/auth/users`, getAuthHeaders())
      return response.data
    },
    enabled: isAdmin(),
  })

  // Delete user mutation
  const deleteMutation = useMutation({
    mutationFn: async (userId: string) => {
      await axios.delete(`${API_BASE}/api/v1/auth/users/${userId}`, getAuthHeaders())
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  // Update user role mutation
  const updateRoleMutation = useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: string }) => {
      await axios.patch(
        `${API_BASE}/api/v1/auth/users/${userId}`,
        { role },
        getAuthHeaders()
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  // Toggle user active status
  const toggleActiveMutation = useMutation({
    mutationFn: async ({ userId, is_active }: { userId: string; is_active: boolean }) => {
      await axios.patch(
        `${API_BASE}/api/v1/auth/users/${userId}`,
        { is_active },
        getAuthHeaders()
      )
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const getRoleBadgeVariant = (role: string) => {
    switch (role) {
      case 'admin':
        return 'destructive' as const
      case 'analyst':
        return 'default' as const
      case 'viewer':
        return 'outline' as const
      case 'client':
        return 'ghost' as const
      default:
        return 'outline' as const
    }
  }

  const getRoleIcon = (role: string) => {
    switch (role) {
      case 'admin':
        return <Shield className="h-3 w-3 mr-1" />
      case 'analyst':
        return <UserCheck className="h-3 w-3 mr-1" />
      case 'viewer':
        return <UserCheck className="h-3 w-3 mr-1" />
      case 'client':
        return <UserX className="h-3 w-3 mr-1" />
      default:
        return null
    }
  }

  if (!isAdmin()) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Access Denied</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">
              You need admin privileges to access the user management page.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">User Management</h1>
          <p className="text-muted-foreground mt-1">
            Manage system users, roles, and permissions
          </p>
        </div>
        <Button disabled title="Coming soon">
          <UserPlus className="h-4 w-4 mr-2" />
          Add User
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{users.length}</div>
            <p className="text-muted-foreground text-sm">Total Users</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">
              {users.filter(u => u.role === 'admin').length}
            </div>
            <p className="text-muted-foreground text-sm">Admins</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">
              {users.filter(u => u.role === 'analyst').length}
            </div>
            <p className="text-muted-foreground text-sm">Analysts</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">
              {users.filter(u => u.is_active).length}
            </div>
            <p className="text-muted-foreground text-sm">Active</p>
          </CardContent>
        </Card>
      </div>

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading users...</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Full Name</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">{user.email}</TableCell>
                    <TableCell>{user.full_name || '-'}</TableCell>
                    <TableCell>
                      <Badge variant={getRoleBadgeVariant(user.role)}>
                        {getRoleIcon(user.role)}
                        {user.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Badge variant={user.is_active ? 'default' : 'outline'}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                        {user.is_verified && (
                          <Badge variant="outline">Verified</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {new Date(user.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        {/* Role selector */}
                        <select
                          value={user.role}
                          onChange={(e) =>
                            updateRoleMutation.mutate({
                              userId: user.id,
                              role: e.target.value,
                            })
                          }
                          disabled={user.id === currentUser?.id}
                          className="text-sm border border-border rounded-md bg-surface px-2 py-1"
                        >
                          <option value="admin">Admin</option>
                          <option value="analyst">Analyst</option>
                          <option value="viewer">Viewer</option>
                          <option value="client">Client</option>
                        </select>

                        {/* Toggle active */}
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            toggleActiveMutation.mutate({
                              userId: user.id,
                              is_active: !user.is_active,
                            })
                          }
                          disabled={user.id === currentUser?.id}
                        >
                          {user.is_active ? 'Deactivate' : 'Activate'}
                        </Button>

                        {/* Delete */}
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => {
                            if (confirm(`Delete user ${user.email}?`)) {
                              deleteMutation.mutate(user.id)
                            }
                          }}
                          disabled={user.id === currentUser?.id}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
