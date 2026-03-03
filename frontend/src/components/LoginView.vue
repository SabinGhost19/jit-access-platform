<script setup>
import { ref } from 'vue'
import { apiLogin } from '../api'

const emit = defineEmits(['authenticated'])
const username = ref('')
const password = ref('')
const error = ref('')

async function submit() {
  error.value = ''
  try {
    const data = await apiLogin(username.value, password.value)
    emit('authenticated', data.accessToken)
  } catch {
    error.value = 'Autentificare eșuată.'
  }
}
</script>

<template>
  <div class="login-box panel">
    <h2>JIT Access Admin</h2>
    <p style="color: var(--muted)">Autentificare administrator</p>
    <div class="field">
      <label>Username</label>
      <input v-model="username" type="text" />
    </div>
    <div class="field">
      <label>Password</label>
      <input v-model="password" type="password" />
    </div>
    <button class="btn btn-primary" @click="submit">Login</button>
    <p v-if="error" style="color: var(--danger)">{{ error }}</p>
  </div>
</template>
