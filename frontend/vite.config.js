import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import basicSsl from '@vitejs/plugin-basic-ssl' // NEW: Import the SSL plugin

export default defineConfig({
  plugins: [react(), basicSsl()], 
  server: {
    host: true, // Needed for Docker
    port: 5173,
    https: true, // NEW: Force Vite to use HTTPS locally
    proxy: {
      '/api': {
        target: 'http://riskwise-backend:8000', // Points to Docker service
        changeOrigin: true,
        secure: false,
      }
    }
  }
})