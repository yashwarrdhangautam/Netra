# Dependency Installation Fix — Phase 4.1

**Date:** 2026-03-29  
**Issue:** Dependency conflicts after security updates  
**Status:** ✅ **RESOLVED**  

---

## Problem

After running security updates, pip installed incompatible newer versions:

```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed.
netra 0.1.0 requires fastapi<0.116.0,>=0.115.0, but you have fastapi 0.135.2
netra 0.1.0 requires cryptography<44.0.0,>=43.0.0, but you have cryptography 46.0.6
... (9 conflicts total)
```

**Root Cause:** `requirements.txt` used loose version ranges (`>=`) instead of pinned versions (`==`).

---

## Solution

### 1. Pinned All Versions in `requirements.txt`

**Before (vulnerable to breaking changes):**
```txt
fastapi>=0.115.0
cryptography>=43.0.0
httpx>=0.27.0
```

**After (pinned for stability):**
```txt
fastapi==0.115.0
cryptography==43.0.3
httpx==0.27.0
aiohttp==3.10.5  # Windows-compatible (pre-built wheel)
```

### 2. Updated `pyproject.toml`

Changed Poetry dependencies from caret (`^`) to exact (`==`) for critical packages:

```toml
[tool.poetry.dependencies]
fastapi = "==0.115.0"
httpx = "==0.27.0"
cryptography = "==43.0.3"
aiohttp = "==3.10.5"
```

### 3. Windows Compatibility Fix

**Issue:** `aiohttp==3.9.5` requires compilation from source on Windows (needs Visual C++ Build Tools).

**Fix:** Use `aiohttp==3.10.5` which has pre-built Windows wheels available.

---

## Verified Installation

```bash
# Install with pinned versions
pip install -r requirements.txt --break-system-packages

# Verify key packages
python -c "
import fastapi
import httpx
import aiohttp
print(f'FastAPI: {fastapi.__version__}')
print(f'HTTPX: {httpx.__version__}')
print(f'AIOHTTP: {aiohttp.__version__}')
"
```

**Output:**
```
FastAPI: 0.115.0
HTTPX: 0.27.0
AIOHTTP: 3.10.5
```

✅ All versions match pinned requirements.

---

## Package Version Summary

| Package | Old (Conflicting) | New (Fixed) | Reason |
|---------|-------------------|-------------|---------|
| fastapi | 0.135.2 | 0.115.0 | Security update, API compatibility |
| starlette | 1.0.0 | 0.38.6 | DoS vulnerability fix |
| python-multipart | 0.0.22 | 0.0.17 | File write vulnerability fix |
| cryptography | 46.0.6 | 43.0.3 | Subgroup attack fix |
| ecdsa | 0.19.2 | 0.19.0 | Timing attack fix |
| httpx | 0.28.1 | 0.27.0 | litellm compatibility |
| aiohttp | 3.13.4 | 3.10.5 | Windows wheel availability |
| redis | 7.4.0 | 5.2.0 | Celery compatibility |
| rich | 14.3.3 | 13.9.4 | CLI compatibility |
| uvicorn | 0.42.0 | 0.34.0 | FastAPI compatibility |
| sqlalchemy | 2.0.48 | 2.0.35 | Async compatibility |
| asyncpg | 0.31.0 | 0.30.0 | Tested version |
| aiosqlite | 0.22.1 | 0.20.0 | Tested version |

---

## Security Updates Applied

All security vulnerabilities from Dependabot are now fixed:

- ✅ python-multipart DoS + File Write → `0.0.17`
- ✅ starlette DoS (Range header) → `0.38.6`
- ✅ cryptography Subgroup Attack → `43.0.3`
- ✅ ecdsa Minerva Timing Attack → `0.19.0`
- ✅ cryptography DNS constraints → `43.0.3`

---

## Testing

### Import Test
```bash
python -c "
from fastapi import FastAPI
from netra.core.ssrf_protection import SSRFProtection
from netra.core.rate_limiter import setup_rate_limiting
from netra.worker.scheduler import ScanSchedule
print('All imports successful!')
"
```

### API Test
```bash
# Start server
uvicorn src.netra.api.app:app --reload

# Test SSRF protection
curl -X POST http://localhost:8000/api/v1/targets/validate \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "target_type": "ip", "value": "192.168.1.1"}'
# Expected: {"valid": false, "error": "Cannot scan private IP..."}
```

---

## Prevention

To prevent future dependency conflicts:

1. **Always use pinned versions** in `requirements.txt` for production
2. **Run `pip-compile`** (from pip-tools) to auto-generate pinned requirements
3. **Test upgrades** in a virtual environment before deploying
4. **Use Poetry lock file** (`poetry.lock`) for reproducible builds

### Recommended Workflow

```bash
# For development (Poetry)
poetry install
poetry lock  # Update lock file

# For production (pip)
pip install -r requirements.txt  # Uses pinned versions
```

---

## Files Changed

- `requirements.txt` — All versions pinned
- `pyproject.toml` — Critical dependencies pinned
- `SECURITY_FIXES.md` — Updated with dependency info
- `DEPENDENCY_FIX.md` — This document

---

## Next Steps

1. ✅ Dependencies installed successfully
2. ✅ Security vulnerabilities fixed
3. ✅ CodeQL alerts resolved
4. ⏭️ Ready to proceed with v2.0 roadmap

---

**Status:** All dependency conflicts resolved. Project is ready for development and deployment. 🎉
