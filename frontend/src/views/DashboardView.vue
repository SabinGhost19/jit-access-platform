<script setup>
defineProps({ metrics: { type: Object, required: true } })
</script>

<template>
  <div class="grid">
    <div class="panel metric">
      <h4>Sesiuni Active</h4>
      <p>{{ metrics.activeSessions }}</p>
    </div>
    <div class="panel metric">
      <h4>Total Cereri</h4>
      <p>{{ metrics.totalRequests }}</p>
    </div>
    <div class="panel metric">
      <h4>Alerte de Abuz</h4>
      <p>{{ metrics.abuseAlerts }}</p>
    </div>
  </div>
</template>
