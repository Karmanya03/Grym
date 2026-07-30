# Intentionally vulnerable fixtures

The compose stack is a local-only test environment for future integration tests. Start it only on a workstation or CI runner you control:

```powershell
docker compose -f tests/fixtures/docker-compose.yml up -d
```

Treat container images as test dependencies: review and pin image digests before using the stack in a long-lived CI environment. No scanner command currently targets these services automatically.

