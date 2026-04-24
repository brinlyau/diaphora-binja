"""
Diaphora Binary Ninja plugin.

Phase 1 registered a single export command. Phase 2 adds the full UI:
  - Diaphora\\Export current BV
  - Diaphora\\Diff against database...
  - Diaphora\\Export and diff...
  - Diaphora\\Show last results

The sidebar widget lives in diaphora_binja_ui.py and is registered lazily
the first time any UI command runs (and at plugin load time when BN's UI
is available). Headless import of this file (no binaryninjaui, no qt) is
supported - it simply skips UI registration.
"""

import os
import sys
import tempfile
import traceback

# Make sure the Diaphora repo root is importable from within BN's plugin env.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
if _REPO_ROOT not in sys.path:
  sys.path.insert(0, _REPO_ROOT)

try:
  import binaryninja
  from binaryninja import PluginCommand, interaction
except ImportError:  # pragma: no cover - outside BN
  binaryninja = None
  PluginCommand = None
  interaction = None

# Detect whether the BN UI process is running. Headless `binaryninja` imports
# (e.g. binja_runner.py) must not pull in binaryninjaui.
HAS_UI = False
if binaryninja is not None:
  try:
    HAS_UI = bool(binaryninja.core_ui_enabled())
  except Exception:
    HAS_UI = False

_ui_module = None
if HAS_UI:
  try:
    import diaphora_binja as _ui_module  # noqa: F401
  except Exception:
    traceback.print_exc()
    _ui_module = None

# Remembers the most recent results DB path so "Show last results" works.
_LAST_RESULTS_DB = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _default_export_name(bv):
  base = "export"
  try:
    if bv is not None and bv.file is not None and bv.file.filename:
      base = os.path.splitext(os.path.basename(bv.file.filename))[0]
  except Exception:
    pass
  return base + ".diaphora.sqlite"


def _ask_save(title, default_name, pattern="*.sqlite"):
  if interaction is None:
    return default_name
  chosen = interaction.get_save_filename_input(title, pattern, default_name)
  return chosen or None


def _ask_open(title, pattern="*.sqlite"):
  if interaction is None:
    return None
  chosen = interaction.get_open_filename_input(title, pattern)
  return chosen or None


def _log(msg):
  try:
    from diaphora_binja import log
    log(msg)
  except Exception:
    print(msg)


def _show_results_sidebar(bv, results_db):
  """Activate the Diaphora sidebar and point it at the given results DB."""
  global _LAST_RESULTS_DB
  _LAST_RESULTS_DB = results_db
  if _ui_module is None:
    _log(f"Results written to {results_db} (sidebar unavailable)")
    return
  try:
    _ui_module.register_sidebar()
  except Exception:
    traceback.print_exc()
  try:
    from binaryninjaui import Sidebar
    Sidebar.current().activate("Diaphora")
  except Exception:
    pass
  sb = _ui_module.get_sidebar_singleton()
  if sb is not None:
    try:
      sb.set_binary_view(bv)
      sb.set_results_db(results_db)
    except Exception:
      traceback.print_exc()


# ---------------------------------------------------------------------------
# command handlers
# ---------------------------------------------------------------------------

def _export_current_bv(bv):
  from diaphora_binja import CBinjaBinDiff

  out_path = _ask_save("Diaphora export DB", _default_export_name(bv))
  if not out_path:
    return

  if _ui_module is not None and hasattr(_ui_module, "ExportTask"):
    def _done(path):
      _log(f"Diaphora export complete: {path}")
    task = _ui_module.ExportTask(bv, out_path, on_done=_done)
    task.start()
    return

  # Fallback: run synchronously
  if os.path.exists(out_path):
    try:
      os.remove(out_path)
    except Exception as exc:
      _log(f"Could not remove existing DB {out_path!r}: {exc}")
      return
  bd = CBinjaBinDiff(bv, out_path)
  if bd.export():
    _log(f"Diaphora export complete: {out_path}")
  else:
    _log(f"Diaphora export FAILED; partial DB at {out_path}")


def _diff_against_db(bv):
  db1 = _ask_open("Diaphora: primary (main) DB")
  if not db1:
    return
  db2 = _ask_open("Diaphora: secondary (diff) DB")
  if not db2:
    return
  out_db = _ask_save("Diaphora: results DB", "diaphora.results.sqlite")
  if not out_db:
    return

  def _done(path):
    _log(f"Diaphora diff complete: {path}")
    _show_results_sidebar(bv, path)

  if _ui_module is not None and hasattr(_ui_module, "DiffTask"):
    task = _ui_module.DiffTask(db1, db2, out_db, on_done=_done)
    task.start()
  else:
    from diaphora_binja import run_diff
    run_diff(db1, db2, out_db)
    _done(out_db)


def _export_and_diff(bv):
  other = _ask_open("Diaphora: other DB to diff against")
  if not other:
    return
  out_db = _ask_save("Diaphora: results DB", "diaphora.results.sqlite")
  if not out_db:
    return
  tmp_fd, tmp_path = tempfile.mkstemp(
    suffix=".diaphora.sqlite",
    prefix=os.path.splitext(_default_export_name(bv))[0] + "_",
  )
  os.close(tmp_fd)

  def _done(path):
    _log(f"Diaphora export+diff complete: {path}")
    _show_results_sidebar(bv, path)
    try:
      if os.path.exists(tmp_path):
        os.remove(tmp_path)
    except Exception:
      pass

  if _ui_module is not None and hasattr(_ui_module, "ExportAndDiffTask"):
    task = _ui_module.ExportAndDiffTask(bv, tmp_path, other, out_db, on_done=_done)
    task.start()
  else:
    from diaphora_binja import CBinjaBinDiff, run_diff
    if os.path.exists(tmp_path):
      try:
        os.remove(tmp_path)
      except Exception:
        pass
    bd = CBinjaBinDiff(bv, tmp_path)
    bd.export()
    run_diff(tmp_path, other, out_db)
    _done(out_db)


def _show_last_results(bv):
  global _LAST_RESULTS_DB
  if not _LAST_RESULTS_DB or not os.path.exists(_LAST_RESULTS_DB):
    chosen = _ask_open("Diaphora: results DB")
    if not chosen:
      return
    _LAST_RESULTS_DB = chosen
  _show_results_sidebar(bv, _LAST_RESULTS_DB)


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

if PluginCommand is not None:
  PluginCommand.register(
    "Diaphora\\Export current BV",
    "Export the current BinaryView to a Diaphora SQLite database",
    _export_current_bv,
  )

  if HAS_UI:
    PluginCommand.register(
      "Diaphora\\Diff against database...",
      "Diff two existing Diaphora SQLite databases and show the results",
      _diff_against_db,
    )
    PluginCommand.register(
      "Diaphora\\Export and diff...",
      "Export the current BinaryView to a temp DB and diff against another",
      _export_and_diff,
    )
    PluginCommand.register(
      "Diaphora\\Show last results",
      "Reopen the Diaphora sidebar against the most recent diff results",
      _show_last_results,
    )

    # Best-effort up-front sidebar registration so the icon appears.
    if _ui_module is not None:
      try:
        _ui_module.register_sidebar()
      except Exception:
        traceback.print_exc()
