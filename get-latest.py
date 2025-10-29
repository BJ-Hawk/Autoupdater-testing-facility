#!/usr/bin/env python3
"""
get_latest.py — updater without GitHub API (no rate limits)
- Fetches remote version.json (with cache-busting, retries).
- Compares to local version.json (if present).
- Downloads & extracts ZIP in-place only if remote > local (or --force).
- Optional SHA256 verification if provided in manifest.

Usage:
  python get_latest.py [--force] [--manifest-url URL] [--retries 12] [--delay 5]

Manifest (minimal expected):
{
  "latest": {
    "version": "1.0.3",
    "zip_url": "https://github.com/YourUser/YourRepo/releases/download/v1.0.3/YourAddon-1.0.3.zip",
    "sha256": "optional-64-hex"
  }
}
"""
import argparse, hashlib, json, re, shutil, sys, tempfile, time, zipfile
from pathlib import Path
from urllib.request import Request, urlopen

# ---------- Defaults (you can override with --manifest-url) ----------
OWNER  = "BJ-Hawk"
REPO   = "Autoupdater-testing-facility"
BRANCH = "main"
DEFAULT_MANIFEST_URL = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/version.json"
# ---------------------------------------------------------------------

CWD = Path.cwd()

def http_get(url: str, accept: str = "application/json") -> bytes:
	req = Request(url, headers={
		"Accept": accept,
		# Be explicit: defeat intermediary caches
		"Cache-Control": "no-cache, no-store, must-revalidate",
		"Pragma": "no-cache",
		"User-Agent": "addon-updater/1.2"
	})
	with urlopen(req) as resp:
		return resp.read()

def parse_version(s: str):
	"""Semver-ish tuple with prerelease ordering (alpha/beta/rc < final)."""
	s = str(s).strip()
	nums = [int(n) for n in re.findall(r"\d+", s)[:3]]
	while len(nums) < 3: nums.append(0)
	prerelease = -1 if re.search(r"(alpha|beta|rc)", s, re.I) else 0
	return (nums[0], nums[1], nums[2], prerelease, s)

def load_local_version_tuple():
	p = CWD / "version.json"
	if not p.exists():
		return None
	try:
		data = json.loads(p.read_text(encoding="utf-8"))
		v = None
		if isinstance(data, dict):
			if "latest" in data and isinstance(data["latest"], dict):
				v = data["latest"].get("version")
			if not v:
				v = data.get("version")
		return parse_version(v) if v else None
	except Exception:
		return None

def fetch_manifest(manifest_url: str, retries: int, delay: float, expect_newer_than=None):
	"""
	Fetch version.json with cache-busting. If expect_newer_than is given,
	retry until remote > expect_newer_than or retries exhausted.
	Returns (remote_json_dict, raw_bytes).
	"""
	last_remote_tuple = None
	last_raw = None
	for i in range(1, retries + 1):
		cb = int(time.time() * 1000)
		url = manifest_url + (("&" if "?" in manifest_url else "?") + f"cb={cb}_{i}")
		try:
			raw = http_get(url, "application/json")
			data = json.loads(raw.decode("utf-8"))
			latest = data.get("latest", data)
			ver = latest.get("version")
			zip_url = latest.get("zip_url")
			if not ver or not zip_url:
				raise RuntimeError("Manifest missing latest.version or latest.zip_url")
			vt = parse_version(ver)
			last_remote_tuple, last_raw = vt, raw
			# If we don't have an expectation, or remote is newer than expectation, return now
			if not expect_newer_than or (vt > expect_newer_than):
				return data, raw
			# Otherwise, wait and retry (CDN may still be stale)
		except Exception as e:
			# Swallow and retry unless last attempt
			if i == retries:
				raise
		time.sleep(delay)
	# If we get here, we never saw newer than expect_newer_than; return the last seen (may be equal/older)
	return json.loads(last_raw.decode("utf-8")), last_raw

def sha256_file(path: Path) -> str:
	h = hashlib.sha256()
	with path.open("rb") as f:
		for chunk in iter(lambda: f.read(1024*1024), b""):
			h.update(chunk)
	return h.hexdigest()

def download_binary(url: str, out_path: Path):
	data = http_get(url, "application/octet-stream")
	out_path.write_bytes(data)

def safe_extract(zip_path: Path, dest_dir: Path):
	with zipfile.ZipFile(zip_path, "r") as z:
		for m in z.infolist():
			# prevent zip-slip
			p = Path(m.filename)
			if any(part == ".." for part in p.parts):
				raise RuntimeError("Unsafe ZIP paths detected (zip-slip).")
		z.extractall(dest_dir)

def extract_in_place(zip_path: Path):
	with zipfile.ZipFile(zip_path, "r") as z:
		files = [n for n in z.namelist() if not n.endswith("/")]
		top = set(n.split("/")[0] for n in files if "/" in n)
		wrapped = (len(top) == 1)

	stage = Path(tempfile.mkdtemp(prefix="addon_stage_"))
	try:
		safe_extract(zip_path, stage)
		if wrapped:
			wrapper = next(stage.iterdir())
			for item in wrapper.iterdir():
				target = CWD / item.name
				if target.exists():
					if target.is_dir(): shutil.rmtree(target)
					else: target.unlink()
				shutil.move(str(item), str(target))
		else:
			for item in stage.iterdir():
				target = CWD / item.name
				if target.exists():
					if target.is_dir(): shutil.rmtree(target)
					else: target.unlink()
				shutil.move(str(item), str(target))
	finally:
		shutil.rmtree(stage, ignore_errors=True)

def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--force", action="store_true", help="Force download & extract even if versions match")
	ap.add_argument("--manifest-url", default=DEFAULT_MANIFEST_URL, help="Override manifest URL")
	ap.add_argument("--retries", type=int, default=12, help="Max manifest fetch attempts (default 12)")
	ap.add_argument("--delay", type=float, default=5.0, help="Seconds between attempts (default 5)")
	args = ap.parse_args()

	local_v = load_local_version_tuple()
	print(f"Local version: {local_v if local_v else '(none)'}")

	# On first try we don't require newer-than; then, if local exists, we expect newer and retry accordingly.
	expect = local_v if local_v and not args.force else None
	remote_data, remote_raw = fetch_manifest(args.manifest_url, args.retries, args.delay, expect_newer_than=expect)

	latest = remote_data.get("latest", remote_data)
	remote_v_str = latest["version"]
	zip_url = latest["zip_url"]
	sha256 = latest.get("sha256")
	remote_v = parse_version(remote_v_str)
	print(f"Remote version: {remote_v} ({remote_v_str})")

	needs_update = args.force or (local_v is None) or (remote_v > local_v)
	if not needs_update:
		# Refresh local manifest anyway (keeps notes/metadata up to date)
		(CWD / "version.json").write_bytes(remote_raw)
		print("Already up to date. Local version.json refreshed.")
		return

	print(f"{'Forcing update' if args.force else 'Update available'} → {zip_url}")
	temp_zip = Path(tempfile.gettempdir()) / "addon-latest.zip"
	download_binary(zip_url, temp_zip)
	print(f"Saved ZIP to {temp_zip}")

	if sha256:
		got = sha256_file(temp_zip)
		if got.lower() != sha256.lower():
			raise RuntimeError(f"SHA256 mismatch! expected {sha256}, got {got}")

	print("Extracting into current folder …")
	extract_in_place(temp_zip)
	print("Extraction complete.")

	# Write the exact remote manifest we used
	(CWD / "version.json").write_bytes(remote_raw)

	try: temp_zip.unlink(missing_ok=True)
	except Exception: pass

	print(f"Done. Now at version {remote_v_str}")

if __name__ == "__main__":
	main()
