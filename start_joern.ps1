Write-Host "Starting Joern server on port 9000..." -ForegroundColor Cyan

# Use Docker to run the Joern server, mounting the current directory
docker run --rm -d `
    --name joern-server `
    -p 9000:9000 `
    ghcr.io/joernio/joern:nightly `
    joern --server --server-host 0.0.0.0 --server-port 9000

Write-Host "Joern container started in background." -ForegroundColor Green
Write-Host "Starting JVM may take up to 30 seconds." -ForegroundColor Yellow
Write-Host "You can view logs using: docker logs -f joern-server" -ForegroundColor Gray
Write-Host "To stop the server later, use: docker stop joern-server" -ForegroundColor Gray
