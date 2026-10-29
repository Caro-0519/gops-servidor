# GOPS · servidor (frontend + backend + base de datos)
- frontend/  : la aplicación web (nginx).
- backend/   : API en Node.js + SQLite (cuenta de acceso, datos, respaldos, IA opcional).
- Los datos viven en el volumen de Docker `gops-data` (archivo /data/gops.db): no se pierden al reconstruir.

Arrancar / actualizar:   docker compose up -d --build
Ver registros:           docker logs gops-backend --tail 30
Respaldo de la base:     docker cp gops-backend:/data/gops.db ./gops-respaldo.db
IA (Gemini): crea el archivo .env (copia .env.example), pon tu llave en IA_API_KEY y ejecuta docker compose up -d --build.
Luego, en la app: Cuenta → "Probar conexión con la IA".
