# Backup, restore and password migration (spec S8)

## Before any change to a running stack

1. Dump the database (consistent, from the running container):

   ```
   docker exec netra-postgres-1 pg_dump -U netra -Fc -d netra > netra-db.dump
   ```

2. Archive the volumes (Postgres volume: stop writes first for a fully consistent copy):

   ```
   docker run --rm -v netra_pg-data:/src:ro -v "<backup-dir>:/dst" alpine tar czf /dst/pg-data-volume.tgz -C /src .
   docker run --rm -v netra_redis-data:/src:ro -v "<backup-dir>:/dst" alpine tar czf /dst/redis-data-volume.tgz -C /src .
   ```

3. Checksum the backup directory: `sha256sum * > SHA256SUMS.txt`.

Keep backups outside the repository. They contain application data.

## Restore (exercised once on 2026-11-18 on a throwaway container)

1. Start a throwaway Postgres container with a generated password. Do not publish its port.
2. Copy the dump in and run `pg_restore -U netra -d netra --no-owner netra-db.dump`.
3. Compare row counts table by table with the live database. The 2026-11-18 drill matched on all 20 tables.
4. Remove the throwaway container.

## Changing the database and Redis passwords on an existing volume

The compose file now requires `NETRA_DB_PASSWORD` and `NETRA_REDIS_PASSWORD` from the environment. Changing the variable does not change the password of a Postgres role that already exists. Migrate in this order:

1. Take the backups above.
2. Change the role password inside the running database:
   `docker exec -it netra-postgres-1 psql -U netra -d netra -c "ALTER USER netra PASSWORD '<new>';"`
3. Set `NETRA_DB_PASSWORD` and `NETRA_REDIS_PASSWORD` in `.env`, then recreate the services:
   `docker compose up -d --force-recreate api worker beat migrations redis postgres`
4. Confirm `/api/v1/health` returns 200 and a worker task runs.

Rollback: restore the previous compose file, and set the old password back with the same `ALTER USER` command.

## Ports

- Postgres, Redis and Ollama are not published by default.
- Developers who need Postgres or Redis on the host use `docker compose -f docker-compose.yml -f docker-compose.dev.yml up`. That override binds them to 127.0.0.1 only.
- The API, frontend and Flower bind to 127.0.0.1.
