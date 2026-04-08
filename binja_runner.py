#!/usr/bin/env python3
"""
Diaphora Binary Ninja headless runner.

Usage:
  python binja_runner.py <binary> [--db out.sqlite] \
                                  [--diff other.sqlite [--diff-out results.sqlite]]

Environment variables honored (mirrors diaphora_ida.py's `main()`):
  DIAPHORA_AUTO          - if set, runs in auto-export mode
  DIAPHORA_EXPORT_FILE   - output sqlite path (required in AUTO mode)
  DIAPHORA_USE_DECOMPILER- enable HLIL-based "decompiler" features (default on)
  DIAPHORA_PROJECT_SCRIPT- optional project hooks script
"""

import os
import sys
import argparse


def _load_bv(path):
  import binaryninja as bn
  bv = bn.load(path, update_analysis=True)
  if bv is None:
    raise RuntimeError(f"Binary Ninja failed to load {path}")
  try:
    bv.update_analysis_and_wait()
  except Exception:
    pass
  return bv


def _run_export(binary_path, db_path):
  from diaphora_binja import CBinjaBinDiff, log

  if os.path.exists(db_path):
    try:
      os.remove(db_path)
      log(f"Removed existing DB {db_path!r}")
    except Exception as exc:
      log(f"Warning: could not remove existing DB: {exc}")

  bv = _load_bv(binary_path)
  bd = CBinjaBinDiff(bv, db_path)

  project_script = os.getenv("DIAPHORA_PROJECT_SCRIPT")
  if project_script:
    bd.project_script = project_script

  use_decompiler = os.getenv("DIAPHORA_USE_DECOMPILER")
  if use_decompiler is not None:
    bd.use_decompiler = bool(int(use_decompiler)) if use_decompiler.isdigit() else True

  if not bd.export():
    raise RuntimeError(
      f"Diaphora export failed; partial DB left at {db_path!r}"
    )
  return bd


def _run_diff(main_db, diff_db, out_db):
  from diaphora_binja import log, run_diff
  log(f"Diffing {main_db} against {diff_db} -> {out_db}")
  run_diff(main_db, diff_db, out_db)
  return out_db


def main():
  # Auto-mode via env vars (parity with diaphora_ida.main())
  if os.getenv("DIAPHORA_AUTO") is not None:
    file_out = os.getenv("DIAPHORA_EXPORT_FILE")
    if file_out is None:
      raise Exception("No export file specified via DIAPHORA_EXPORT_FILE")
    binary = os.getenv("DIAPHORA_BINARY") or (sys.argv[1] if len(sys.argv) > 1 else None)
    if binary is None:
      raise Exception("No binary specified (set DIAPHORA_BINARY or pass as argv[1])")
    _run_export(binary, file_out)
    return 0

  parser = argparse.ArgumentParser(description="Diaphora Binary Ninja headless runner")
  parser.add_argument("binary", help="Path to binary to analyse")
  parser.add_argument("--db", default=None, help="Output SQLite DB path")
  parser.add_argument("--diff", default=None, help="Optional second DB to diff against")
  parser.add_argument(
    "--diff-out",
    default=None,
    help="Where to write diff results (default: <db>.results.sqlite next to --db)",
  )
  args = parser.parse_args()

  db_path = args.db or (os.path.splitext(os.path.basename(args.binary))[0] + ".diaphora.sqlite")
  _run_export(args.binary, db_path)

  if args.diff:
    out_db = args.diff_out or (os.path.splitext(db_path)[0] + ".results.sqlite")
    _run_diff(db_path, args.diff, out_db)

  return 0


if __name__ == "__main__":
  sys.exit(main())
