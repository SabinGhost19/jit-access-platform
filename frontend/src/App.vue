<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { apiGet, apiPost } from './api'
import LoginView from './components/LoginView.vue'
import DashboardView from './views/DashboardView.vue'
import SessionsView from './views/SessionsView.vue'
import AuditView from './views/AuditView.vue'

const token = ref(localStorage.getItem('jit_admin_token') || '')
const currentTab = ref('dashboard')
const theme = ref(localStorage.getItem('jit_theme') || 'light')

const metrics = ref({ activeSessions: 0, totalRequests: 0, abuseAlerts: 0 })
const sessions = ref([])
const logs = ref([])
const auditQuery = ref('')

const isAuthenticated = computed(() => Boolean(token.value))

watch(theme, (nextTheme) => {
  localStorage.setItem('jit_theme', nextTheme)
  document.documentElement.classList.toggle('dark', nextTheme === 'dark')
}, { immediate: true })

watch(auditQuery, async () => {
  if (!isAuthenticated.value) return
  const search = auditQuery.value ? `?query=${encodeURIComponent(auditQuery.value)}` : ''
  logs.value = await apiGet(`/audit${search}`, token.value)
})

async function loadData() {
  metrics.value = await apiGet('/dashboard', token.value)
  sessions.value = await apiGet('/sessions', token.value)
  logs.value = await apiGet('/audit', token.value)
}

async function revokeSession(row) {
  await apiPost(`/sessions/${row.requestNamespace}/${row.requestName}/revoke`, token.value)
  await loadData()
}

function onAuth(newToken) {
  token.value = newToken
  localStorage.setItem('jit_admin_token', newToken)
  loadData()
}

function logout() {
  token.value = ''
  localStorage.removeItem('jit_admin_token')
}

function toggleTheme() {
  theme.value = theme.value === 'light' ? 'dark' : 'light'
}

onMounted(() => {
  if (isAuthenticated.value) {
    loadData()
  }
})
</script>

<template>
  <LoginView v-if="!isAuthenticated" @authenticated="onAuth" />

  <main v-else class="app-shell">
    <div class="toolbar">
      <h2>JIT Access Admin</h2>
      <div style="display:flex; gap:8px;">
        <button class="btn tab" @click="toggleTheme">{{ theme === 'light' ? 'Dark Mode' : 'Light Mode' }}</button>
        <button class="btn tab" @click="logout">Logout</button>
      </div>
    </div>

    <div class="nav-tabs" style="margin-bottom: 14px;">
      <button class="tab" :class="{ active: currentTab === 'dashboard' }" @click="currentTab = 'dashboard'">Dashboard</button>
      <button class="tab" :class="{ active: currentTab === 'sessions' }" @click="currentTab = 'sessions'">Sessions Table</button>
      <button class="tab" :class="{ active: currentTab === 'audit' }" @click="currentTab = 'audit'">Audit Logs</button>
    </div>

    <DashboardView v-if="currentTab === 'dashboard'" :metrics="metrics" />
    <SessionsView v-if="currentTab === 'sessions'" :sessions="sessions" @revoke="revokeSession" />
    <AuditView v-if="currentTab === 'audit'" :logs="logs" v-model:query="auditQuery" />
  </main>
</template>
