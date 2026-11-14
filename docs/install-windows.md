# Install NETRA on Windows

NETRA runs as Docker containers. On Windows the simplest supported route is Docker Desktop with the WSL 2 backend. The scanner tools are Linux programs, so they run inside the containers, not on Windows itself.

Status: these steps are written from the repository's compose file and installation guide. They have not yet been run end to end on a clean Windows machine. Treat the first run as the test.

## What you need

- Windows 10 (22H2) or Windows 11, 64-bit
- 8 GB RAM minimum, 16 GB recommended
- 20 GB free disk space
- Virtualisation enabled in BIOS/UEFI
- Git for Windows

## 1. Install WSL 2 and Docker Desktop

1. Open PowerShell as Administrator and run:
   `wsl --install`
   Restart when asked.
2. Download Docker Desktop from https://www.docker.com/products/docker-desktop/ and install it.
3. Open Docker Desktop, go to Settings > General, and check **Use the WSL 2 based engine**.
4. Go to Settings > Resources > WSL Integration and enable your default Linux distribution.
5. Confirm Docker works. In PowerShell:
   `docker version`
   `docker compose version`

## 2. Get the code

```powershell
git clone https://github.com/<owner>/netra.git
cd netra
```

## 3. Create your settings file

```powershell
copy .env.example .env
```

Open `.env` in a text editor and set a long random JWT secret. Generate one in PowerShell:

```powershell
[Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }) -as [byte[]])
```

Paste the output after `NETRA_JWT_SECRET_KEY=`. The stack will not start without it.

Do not put real API keys in `.env` unless you need that integration. Never commit `.env`.

## 4. Start the stack

```powershell
docker compose up -d --build
docker compose ps
```

Wait until the `api` service is healthy. Check it:

```powershell
curl.exe http://localhost:8000/health
```

If port 8000 is already in use, change the host port of the `api` service in `docker-compose.yml`.

## 5. Create the first admin account

```powershell
docker compose exec -it api python -m netra.cli.create_admin
```

Choose a strong password. Then open the GUI at http://localhost:5173 and sign in.

## 6. Optional: sync the pinned data sets

The payload library and nuclei templates are fetched at pinned commits on the worker:

```powershell
docker compose exec worker python -c "from netra.core.config import settings; from netra.intel.payloads import sync_checkout; from netra.scanner.tools.template_pin import sync_pinned; sync_checkout(settings.tools_dir); sync_pinned(settings.tools_dir)"
```

## Troubleshooting

- **"NETRA_JWT_SECRET_KEY must be set"**: the value is missing from `.env`, or the file is not in the folder you started from.
- **Containers exit straight away**: run `docker compose logs api` and read the first error.
- **WSL errors on startup**: run `wsl --update`, then restart Docker Desktop.
- **Slow first build**: the worker image compiles several Go tools. Expect 10 to 20 minutes the first time.

## Stop and clean up

```powershell
docker compose down
```

Add `-v` only if you want to delete the database as well.
