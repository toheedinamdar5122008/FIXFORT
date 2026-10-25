import react from '@vitejs/plugin-react'
// Port 5173 is fixed on purpose: the backend and the clinic only allow this origin (CORS). If 5173 is busy,
// Vite now stops with an error instead of silently moving to 5174, which would break every API call.
export default { plugins: [react()], server: { port: 5173, strictPort: true }, preview: { port: 5173, strictPort: true } }
