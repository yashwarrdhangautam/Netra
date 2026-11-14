# Install NETRA on Kali Linux

Kali is the natural home for NETRA: most scanner tools are already there. The stack still runs in Docker, so the containers carry their own copies of the tools.

Status: written from the repository's compose file and installation guide. Not yet run end to end on a clean Kali VM. Treat the first run as the test.

## What you need

- Kali Linux 2024.x or later, 64-bit, on bare metal or a VM
- 8 GB RAM minimum, 16 GB recommended
- 20 GB free disk space
- A user with sudo rights

## 1. Install Docker and Compose

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in so the group change applies. Then check:

```bash
docker version
docker compose version
```

If `docker-compose-plugin` is not found, install the Compose plugin from Docker's own repository (https://docs.docker.com/engine/install/debian/), since Kali is Debian-based.

## 2. Get the code

```bash
git clone https://github.com/<owner>/netra.git
cd netra
```

## 3. Create your settings file

```bash
cp .env.example .env
openssl rand -base64 48
```

Paste the output into `.env` after `NETRA_JWT_SECRET_KEY=`. The stack refuses to start without it. Never commit `.env`.

## 4. Start the stack

```bash
docker compose up -d --build
docker compose ps
curl -s http://localhost:8000/health
```

If port 8000 is taken on Kali (some local tools use it), change the host port of the `api` service in `docker-compose.yml`.

## 5. Create the first admin account

```bash
docker compose exec -it api python -m netra.cli.create_admin
```

Open http://localhost:5173 and sign in.

## 6. Optional: sync the pinned data sets

```bash
docker compose exec worker python -c "from netra.core.config import settings; from netra.intel.payloads import sync_checkout; from netra.scanner.tools.template_pin import sync_pinned; sync_checkout(settings.tools_dir); sync_pinned(settings.tools_dir)"
```

## 7. Optional: use the Kali tools on the host

The containers already include the scanners. You only need Kali's copies for manual work. NETRA does not read them.

## Troubleshooting

- **Permission denied on the Docker socket**: the group change has not applied. Log out and back in, or run `newgrp docker`.
- **`docker compose` not found**: install the Compose plugin as described above.
- **Port already in use**: find the process with `sudo ss -ltnp | grep 8000` and stop it, or change the port in `docker-compose.yml`.
- **Slow first build**: the worker image compiles several Go tools. Expect 10 to 20 minutes.

## Stop and clean up

```bash
docker compose down
```

Add `-v` only if you want to delete the database as well.
