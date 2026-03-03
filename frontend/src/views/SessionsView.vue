<script setup>
defineProps({ sessions: { type: Array, required: true } })
const emit = defineEmits(['revoke'])

function revoke(session) {
  emit('revoke', session)
}
</script>

<template>
  <div class="panel table-wrap">
    <table class="table">
      <thead>
        <tr>
          <th>Identitate</th>
          <th>Țintă</th>
          <th>Motiv</th>
          <th>Expirare</th>
          <th>Status</th>
          <th>Acțiune</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in sessions" :key="`${row.requestNamespace}:${row.requestName}`">
          <td>{{ row.identity }}</td>
          <td>{{ row.target }}</td>
          <td>{{ row.reason }}</td>
          <td>{{ row.expiresAt || '-' }}</td>
          <td><span class="badge">{{ row.status }}</span></td>
          <td>
            <button
              v-if="row.status === 'ACTIVE'"
              class="btn btn-danger"
              @click="revoke(row)"
            >
              Revoke Now
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
