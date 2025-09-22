1. Generate TLS materials
   cd certs
   chmod +x generate-certs.sh
   ./generate-certs.sh

2. Start stack
   docker compose up --build

3. Verify mTLS works
   the app-probe container should print a timestamp from select now()

4. Replace app-probe with your real backend later
   mount the same client cert files into your backend container
   connect to Postgres with sslmode=verify-full and the provided certs
