<script setup>
defineProps({ logs: { type: Array, required: true } })
const query = defineModel('query')
</script>

<template>
  <div class="panel table-wrap">
    <div style="margin-bottom: 10px;">
      <input v-model="query" class="field search" placeholder="Caută identitate, acțiune, mesaj..." />
    </div>
    <table class="table">
      <thead>
        <tr>
          <th>Timp</th>
          <th>Identitate</th>
          <th>Acțiune</th>
          <th>Status</th>
          <th>Mesaj</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in logs" :key="row.id">
          <td>{{ row.timestamp }}</td>
          <td>{{ row.identity }}</td>
          <td>{{ row.action }}</td>
          <td><span class="badge">{{ row.status }}</span></td>
          <td>{{ row.message }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
