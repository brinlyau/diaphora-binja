"""
Diaphora Binary Ninja frontend (Phase 1: headless exporter).

Port of diaphora_ida.py's exporter surface to Binary Ninja. The core diffing
engine in diaphora.py is disassembler-agnostic and is reused unchanged; this
file's job is to produce the same `props` tuple that diaphora_ida.py's
`read_function` does, so that `CBinDiff.save_function` can persist it.

Notes:
  - BN <-> BN diffing should work fully. BN exported DBs will NOT match IDA
    exported DBs on IR-derived hash fields (microcode / pseudo hashes),
    because BN MLIL/HLIL are not Hex-Rays microcode/ctree.
  - Pure graph-math helpers (MD-index, KGH, SPP accumulation, SCC, topo sort)
    are ported verbatim from diaphora_ida.py; only the data source changes.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

import os
import re
import sys
import time
import json
import decimal
import sqlite3
import traceback

from hashlib import md5

try:
  import binaryninja as bn
  from binaryninja import (
    BinaryView,
    Function,
    SymbolType,
    MediumLevelILOperation,
    HighLevelILOperation,
  )
except ImportError:
  bn = None  # allow syntax/import testing without BN

import diaphora
import diaphora_config as config

from others.tarjan_sort import strongly_connected_components, robust_topological_sort
from jkutils.factor import primesbelow


# ------------------------------------------------------------------------------
def log(message):
  print(f"[Diaphora-BN: {time.asctime()}] {message}")


def log_refresh(message, show=False, do_log=True):
  if do_log:
    log(message)


def debug_refresh(message):
  if os.getenv("DIAPHORA_DEBUG"):
    log(message)


# Route diaphora.py's logging through ours.
#
# When loaded as the BN plugin, `import diaphora` resolves to the package whose
# __init__.py loads diaphora.py under the synthetic name `diaphora._engine` and
# then copies its symbols into the package globals.  CBinDiff methods reference
# `log` via their module's __globals__, which is `diaphora._engine.__dict__` --
# not the package -- so assigning to `diaphora.log` alone has no effect on
# logging emitted from inside the engine.  Override on the engine module too
# whenever it is present.  In the headless path (binja_runner.py) `diaphora` is
# the diaphora.py module itself, so the first assignment is what matters.
diaphora.log = log
diaphora.log_refresh = log_refresh
_engine = sys.modules.get("diaphora._engine")
if _engine is not None:
  _engine.log = log
  _engine.log_refresh = log_refresh


# ------------------------------------------------------------------------------
# KGH (Koret-Karamitas) feature primes.  Copied from jkutils/graph_hashes.py so
# we don't need to import the IDA-coupled module.
NODE_ENTRY = 2
NODE_EXIT = 3
NODE_NORMAL = 5
EDGE_IN_CONDITIONAL = 7
EDGE_OUT_CONDITIONAL = 11
FEATURE_LOOP = 19
FEATURE_CALL = 23
FEATURE_DATA_REFS = 29
FEATURE_CALL_REF = 31
FEATURE_STRONGLY_CONNECTED = 37
FEATURE_FUNC_NO_RET = 41
FEATURE_FUNC_LIB = 43
FEATURE_FUNC_THUNK = 47


# ------------------------------------------------------------------------------
# Fake IDA-style function flag bits so downstream heuristics that look at
# `function_flags & FUNC_*` keep working on BN-exported DBs.
FUNC_NORET = 0x00000001
FUNC_LIB = 0x00000004
FUNC_THUNK = 0x00000080


# ------------------------------------------------------------------------------
class CHLILAstVisitor:
  """
  Walks Binary Ninja HLIL AST and accumulates a primes product over operation
  types.  Mirrors `CAstVisitor` in diaphora_ida.py which multiplies primes by
  Hex-Rays ctree op ids.
  """

  def __init__(self):
    self.primes = primesbelow(4096)
    self.primes_hash = 1

  def _op_index(self, op):
    try:
      # HighLevelILOperation members behave like an enum.
      return int(op.value)
    except Exception:
      try:
        return int(op)
      except Exception:
        return 0

  def visit(self, node):
    if node is None:
      return
    try:
      op = getattr(node, "operation", None)
      if op is not None:
        idx = self._op_index(op) % len(self.primes)
        self.primes_hash *= self.primes[idx]
    except Exception:
      pass

    # Recurse over operands when they look like HLIL nodes.
    try:
      operands = getattr(node, "operands", None)
    except Exception:
      operands = None

    if operands is None:
      return

    for sub in operands:
      # Operands can be other HLIL instructions, variables, ints, lists, ...
      if sub is None:
        continue
      if isinstance(sub, (list, tuple)):
        for item in sub:
          if hasattr(item, "operation") or hasattr(item, "operands"):
            self.visit(item)
      elif hasattr(sub, "operation") or hasattr(sub, "operands"):
        self.visit(sub)


# ------------------------------------------------------------------------------
def _func_no_return(func):
  """True if Binary Ninja analysis says @func cannot return.

  ``Function.can_return`` returns a ``BoolWithConfidence`` in modern BN, which
  is never identical to the singleton ``False`` -- so ``can_return is False``
  silently misses every no-return function.  Use truthiness instead, defaulting
  to True (i.e. ``not no-return``) when the attribute is missing or raises.
  """
  try:
    cr = getattr(func, "can_return", True)
  except Exception:
    return False
  try:
    return not bool(cr)
  except Exception:
    return False


# ------------------------------------------------------------------------------
def _constant_filter(value):
  """Identical heuristic to the IDA frontend."""
  try:
    value = int(value)
  except Exception:
    return False
  if value < 0x1000:
    return False
  if (
    value & 0xFFFFFF00 == 0xFFFFFF00
    or value & 0xFFFF00 == 0xFFFF00
    or value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00
    or value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00
  ):
    return False
  for i in range(64):
    if value == (1 << i):
      return False
  return True


# ------------------------------------------------------------------------------
class CBinjaBinDiff(diaphora.CBinDiff):
  """
  Binary Ninja frontend for Diaphora.
  """

  def __init__(self, bv, db_name):
    diaphora.CBinDiff.__init__(self, db_name)
    # open_db() only sets self.db on the main thread; on BN background threads
    # self.db stays None.  Repair that here so commit_and_start_transaction works.
    if self.db is None:
      self.db = self.get_db()
      self.create_schema()
    self.bv = bv
    self.decompiler_available = True
    self.names = {}
    if bv is not None:
      try:
        for sym in bv.get_symbols():
          try:
            self.names[int(sym.address)] = sym.full_name or sym.name
          except Exception:
            pass
      except Exception:
        pass
      self.min_ea = int(bv.start)
      self.max_ea = int(bv.end)
      self.image_base = int(bv.start)
      try:
        self.arch = bv.arch.name if bv.arch is not None else ""
      except Exception:
        self.arch = ""
    else:
      self.min_ea = 0
      self.max_ea = 0
      self.image_base = 0
      self.arch = ""

    # Cached per-export state (mirrors diaphora_ida.py)
    self.pseudo = {}
    self.pseudo_hash = {}
    self.pseudo_comments = {}
    self.microcode = {}

    # Cache the mnemonic list so mnemonics_spp is deterministic for a given BV.
    self._cpu_ins_list = None

    self.project_script = None
    self.hooks = None

  # ----------------------------------------------------------------------------
  def get_base_address(self):
    return self.image_base

  def clear_pseudo_fields(self):
    self.pseudo = {}
    self.pseudo_hash = {}
    self.pseudo_comments = {}
    self.microcode = {}

  # ----------------------------------------------------------------------------
  # Helpers over a BN function / BV.
  # ----------------------------------------------------------------------------
  def _iter_instruction_addrs(self, bb):
    """Yield every instruction address in a BN BasicBlock."""
    addr = bb.start
    end = bb.end
    bv = self.bv
    while addr < end:
      length = bv.get_instruction_length(addr)
      if not length or length <= 0:
        break
      yield addr
      addr += length

  def _get_instruction_text(self, addr):
    """Return (mnemonic, full_disasm_string) for an instruction."""
    try:
      tokens, _ = self.bv.arch.get_instruction_text(self.bv.read(addr, 16), addr)
    except Exception:
      tokens = None
    if not tokens:
      return "", ""
    mnem = str(tokens[0]).strip()
    disasm = "".join(str(t) for t in tokens).strip()
    return mnem, disasm

  def _get_instruction_length(self, addr):
    try:
      length = self.bv.get_instruction_length(addr)
    except Exception:
      length = 0
    return length or 1

  def _get_bytes(self, addr, length):
    try:
      data = self.bv.read(addr, length)
      if data is None:
        return b""
      return bytes(data)
    except Exception:
      return b""

  def _extract_callers(self, func):
    callers = []
    try:
      for ref in self.bv.get_code_refs(func.start):
        try:
          caller_func = ref.function
        except Exception:
          caller_func = None
        if caller_func is None:
          continue
        ea = int(caller_func.start)
        if ea not in callers:
          callers.append(ea)
    except Exception:
      pass
    return callers

  def _extract_callees_and_refs(self, func, addr):
    """Return (callee_func_starts_at_this_insn, data_ref_targets_at_this_insn)."""
    callees = []
    data_refs = []
    try:
      for cref in self.bv.get_code_refs_from(addr):
        cfunc = self.bv.get_functions_containing(cref)
        if cfunc:
          for cf in cfunc:
            if int(cf.start) != int(func.start):
              callees.append(int(cf.start))
    except Exception:
      pass
    try:
      for dref in self.bv.get_data_refs_from(addr):
        data_refs.append(int(dref))
    except Exception:
      pass
    return callees, data_refs

  def _is_call_insn(self, func, addr):
    try:
      ilist = func.get_low_level_il_at(addr)
      if ilist is None:
        return False
      op = getattr(ilist, "operation", None)
      if op is None:
        return False
      name = getattr(op, "name", str(op))
      return "CALL" in name
    except Exception:
      return False

  # ----------------------------------------------------------------------------
  def get_mnemonic_list(self):
    """Build a stable sorted list of mnemonics for the current arch/bv."""
    if self._cpu_ins_list is not None:
      return self._cpu_ins_list
    mnems = set()
    try:
      for func in self.bv.functions:
        for bb in func.basic_blocks:
          for addr in self._iter_instruction_addrs(bb):
            mnem, _ = self._get_instruction_text(addr)
            if mnem:
              mnems.add(mnem)
    except Exception:
      pass
    self._cpu_ins_list = sorted(mnems)
    return self._cpu_ins_list

  # ----------------------------------------------------------------------------
  # MLIL-based "microcode" replacement.
  # ----------------------------------------------------------------------------
  def get_microcode(self, func):
    """
    Return (bblocks, bb_relations) in the same shape used by
    save_microcode_instructions, plus populate self.microcode[ea] with a
    normalized text representation. Also returns a spp hash contribution.
    """
    ea = int(func.start)
    bblocks = {}
    bb_relations = {}
    lines = []
    spp = 1
    primes = self.primes
    mlil = None
    try:
      mlil = func.mlil
    except Exception:
      mlil = None
    if mlil is None:
      self.microcode[ea] = []
      return bblocks, bb_relations, spp

    try:
      mlil_bbs = list(mlil.basic_blocks)
    except Exception:
      mlil_bbs = []

    bb_index = {}
    for i, bb in enumerate(mlil_bbs, start=1):
      bb_index[bb.start] = i
      bb_lines = []
      try:
        insns = list(bb)
      except Exception:
        insns = []
      for ins in insns:
        try:
          op = getattr(ins, "operation", None)
          if op is not None:
            op_name = getattr(op, "name", str(op))
          else:
            op_name = str(type(ins).__name__)
        except Exception:
          op_name = "UNK"
        text = f"{op_name.lower()} {str(ins)}"
        bb_lines.append(
          {
            "address": getattr(ins, "address", ea),
            "line": text,
            "mnemonic": op_name.lower(),
            "color_line": text,
            "comments": None,
          }
        )
        lines.append(text)
        try:
          idx = int(op)
        except Exception:
          try:
            idx = int(getattr(op, "value", 0))
          except Exception:
            idx = 0
        spp *= primes[idx % len(primes)]

      bblocks[i] = {"start": bb.start, "end": bb.end, "lines": bb_lines}

    for bb in mlil_bbs:
      i = bb_index.get(bb.start)
      if i is None:
        continue
      try:
        for edge in bb.outgoing_edges:
          tgt = bb_index.get(edge.target.start)
          if tgt is None:
            continue
          bb_relations.setdefault(i, []).append(tgt)
      except Exception:
        pass

    self.microcode[ea] = lines
    return bblocks, bb_relations, spp

  # ----------------------------------------------------------------------------
  # HLIL-based pseudo primes hash.
  # ----------------------------------------------------------------------------
  def get_pseudocode_primes(self, func):
    try:
      hlil = func.hlil
    except Exception:
      hlil = None
    if hlil is None:
      return 1, None, []
    visitor = CHLILAstVisitor()
    try:
      root = getattr(hlil, "root", None)
      if root is not None:
        visitor.visit(root)
      else:
        for ins in hlil.instructions:
          visitor.visit(ins)
    except Exception:
      pass

    # A cheap textual pseudocode so pseudo/ pseudo_lines have a value.
    pseudo_lines = []
    try:
      for ins in hlil.instructions:
        pseudo_lines.append(str(ins))
    except Exception:
      pass

    return visitor.primes_hash, "\n".join(pseudo_lines) if pseudo_lines else None, pseudo_lines

  # ----------------------------------------------------------------------------
  # Pure-math helpers copied verbatim from diaphora_ida.py.
  # ----------------------------------------------------------------------------
  def extract_function_mdindex(
    self, bb_topological, bb_topological_sorted, bb_edges, bb_topo_num, bb_degree
  ):
    md_index = 0
    if bb_topological:
      bb_topo_order = {}
      for i, scc in enumerate(bb_topological_sorted):
        for bb in scc:
          bb_topo_order[bb] = i
      tuples = []
      for src, dst in bb_edges:
        tuples.append(
          (
            bb_topo_order[bb_topo_num[src]],
            bb_degree[src][0],
            bb_degree[src][1],
            bb_degree[dst][0],
            bb_degree[dst][1],
          )
        )
      rt2, rt3, rt5, rt7 = (decimal.Decimal(p).sqrt() for p in (2, 3, 5, 7))
      emb_tuples = (
        sum((z0, z1 * rt2, z2 * rt3, z3 * rt5, z4 * rt7))
        for z0, z1, z2, z3, z4 in tuples
      )
      md_index = sum((1 / emb_t.sqrt() for emb_t in emb_tuples))
      md_index = str(md_index)
    return md_index

  def extract_function_topological_information(self, bb_relations, bb_topological):
    loops = 0
    strongly_connected = None
    strongly_connected_spp = 0
    bb_topological_sorted = None
    try:
      strongly_connected = strongly_connected_components(bb_relations)
      bb_topological_sorted = robust_topological_sort(bb_topological)
      bb_topological = json.dumps(bb_topological_sorted)
      strongly_connected_spp = 1
      for item in strongly_connected:
        val = len(item)
        if val > 1:
          strongly_connected_spp *= self.primes[val]
    except RecursionError:
      strongly_connected = []
      bb_topological = None
    except Exception:
      traceback.print_exc()
      strongly_connected = []
      bb_topological = None

    loops = 0
    for sc in strongly_connected or []:
      if len(sc) > 1:
        loops += 1
      else:
        if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
          loops += 1

    return (
      bb_topological,
      bb_topological_sorted,
      strongly_connected,
      loops,
      strongly_connected_spp,
    )

  # ----------------------------------------------------------------------------
  # KGH hash port (pure math, but needs BN for per-bb feature extraction).
  # ----------------------------------------------------------------------------
  def calculate_kgh(self, func):
    try:
      flow = list(func.basic_blocks)
    except Exception:
      return "NO-FLOW-GRAPH"
    if not flow:
      return "NO-FLOW-GRAPH"

    h = 1
    bb_relations = {}
    for block in flow:
      succs = []
      preds = []
      try:
        for e in block.outgoing_edges:
          succs.append(e.target)
        for e in block.incoming_edges:
          preds.append(e.source)
      except Exception:
        pass

      # node value
      nv = 1
      if len(preds) == 0:
        nv *= NODE_ENTRY
      if len(succs) == 0:
        nv *= NODE_EXIT
      nv *= NODE_NORMAL
      h *= nv

      # edges value
      ev = 1
      for _ in succs:
        ev *= EDGE_OUT_CONDITIONAL
      for _ in preds:
        ev *= EDGE_IN_CONDITIONAL
      h *= ev

      bb_start = int(block.start)
      bb_relations.setdefault(bb_start, [])
      for s in succs:
        bb_relations[bb_start].append(int(s.start))
      for p in preds:
        bb_relations.setdefault(int(p.start), []).append(bb_start)

      for addr in self._iter_instruction_addrs(block):
        if self._is_call_insn(func, addr):
          h *= FEATURE_CALL
        _, data_refs = self._extract_callees_and_refs(func, addr)
        if data_refs:
          h *= FEATURE_DATA_REFS
        try:
          for cref in self.bv.get_code_refs_from(addr):
            containing = self.bv.get_functions_containing(cref)
            if not containing or all(int(cf.start) != int(func.start) for cf in containing):
              h *= FEATURE_CALL_REF
        except Exception:
          pass

    try:
      scc = strongly_connected_components(bb_relations)
      for sc in scc:
        if len(sc) > 1:
          h *= FEATURE_LOOP
        elif sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
          h *= FEATURE_LOOP
      h *= FEATURE_STRONGLY_CONNECTED ** len(scc)
    except Exception:
      pass

    # Function-level flags (from BN symbol / analysis)
    if _func_no_return(func):
      h *= FEATURE_FUNC_NO_RET
    try:
      sym = func.symbol
      if sym is not None and sym.type == SymbolType.LibraryFunctionSymbol:
        h *= FEATURE_FUNC_LIB
    except Exception:
      pass
    try:
      if getattr(func, "is_thunk", False):
        h *= FEATURE_FUNC_THUNK
    except Exception:
      pass

    return str(h)

  # ----------------------------------------------------------------------------
  def _function_flags(self, func):
    flags = 0
    if _func_no_return(func):
      flags |= FUNC_NORET
    try:
      sym = func.symbol
      if sym is not None and sym.type == SymbolType.LibraryFunctionSymbol:
        flags |= FUNC_LIB
    except Exception:
      pass
    try:
      if getattr(func, "is_thunk", False):
        flags |= FUNC_THUNK
    except Exception:
      pass
    return flags

  def _function_prototype(self, func):
    try:
      ft = func.function_type
      if ft is not None:
        return str(ft)
    except Exception:
      pass
    try:
      return str(func.type)
    except Exception:
      return ""

  # ----------------------------------------------------------------------------
  # The big one.
  # ----------------------------------------------------------------------------
  def read_function(self, func):
    """
    Port of diaphora_ida.py's read_function. Returns the same 54-element
    props tuple so CBinDiff.save_function can persist it.
    """
    if func is None:
      return False

    export_time = time.monotonic()
    image_base = self.get_base_address()
    f = int(func.start)

    try:
      name = func.symbol.full_name if func.symbol is not None else func.name
    except Exception:
      name = func.name or f"sub_{f:x}"
    true_name = func.name or name

    if self.hooks is not None and "before_export_function" in dir(self.hooks):
      if not self.hooks.before_export_function(f, name):
        return False

    if self.exclude_library_thunk:
      try:
        if getattr(func, "is_thunk", False):
          debug_refresh(f"Skipping thunk function {name!r}")
          return False
      except Exception:
        pass
      try:
        sym = func.symbol
        if sym is not None and sym.type == SymbolType.LibraryFunctionSymbol:
          debug_refresh(f"Skipping library function {name!r}")
          return False
      except Exception:
        pass

    if not self.ida_subs:
      if (
        name.startswith("sub_")
        or name.startswith("j_")
        or name.startswith("unknown")
        or name.startswith("nullsub_")
      ):
        return False

    # Per-function accumulators mirror diaphora_ida.py.
    size = 0
    nodes = 0
    edges = 0
    instructions = 0
    mnems = []
    names_set = set()
    bytes_hash_parts = []
    bytes_sum = 0
    function_hash_parts = []
    outdegree = 0
    indegree = 0
    assembly = {}
    basic_blocks_data = {}
    bb_relations = {}
    bb_topo_num = {}
    bb_topological = {}
    switches = []
    bb_degree = {}
    bb_edges = []
    constants = []

    callers = self._extract_callers(func)
    callees = []

    try:
      indegree = len(list(self.bv.get_code_refs(f)))
    except Exception:
      indegree = 0

    mnemonics_spp = 1
    cpu_ins_list = self.get_mnemonic_list()

    current_head = f
    try:
      blocks = list(func.basic_blocks)
    except Exception:
      blocks = []

    for block in blocks:
      nodes += 1
      instructions_data = []

      block_ea = int(block.start) - image_base
      idx = len(bb_topological)
      bb_topological[idx] = []
      bb_topo_num[block_ea] = idx

      for current_head in self._iter_instruction_addrs(block):
        mnem, disasm = self._get_instruction_text(current_head)
        ilen = self._get_instruction_length(current_head)
        size += ilen
        instructions += 1

        if mnem in cpu_ins_list:
          try:
            mnemonics_spp *= self.primes[cpu_ins_list.index(mnem)]
          except Exception:
            pass

        rel_head = current_head - image_base
        if block_ea in assembly:
          assembly[block_ea].append([rel_head, disasm])
        else:
          if nodes == 1:
            assembly[block_ea] = [[rel_head, disasm]]
          else:
            assembly[block_ea] = [
              [rel_head, "loc_%x:" % current_head],
              [rel_head, disasm],
            ]

        curr_bytes = self._get_bytes(current_head, ilen)
        if curr_bytes:
          bytes_hash_parts.append(curr_bytes)
          bytes_sum += sum(curr_bytes)
          function_hash_parts.append(curr_bytes)

        # Callees + names + constants
        insn_callees, data_refs = self._extract_callees_and_refs(func, current_head)
        for ce in insn_callees:
          if ce not in callees:
            callees.append(ce)

        try:
          outdegree += len(list(self.bv.get_code_refs_from(current_head)))
        except Exception:
          pass

        mnems.append(mnem)

        tmp_name = None
        tmp_type = None
        for dref in data_refs:
          if dref in self.names:
            tmp_name = self.names[dref]
            try:
              sym = self.bv.get_symbol_at(dref)
              if sym is not None:
                tmp_type = str(sym.type)
            except Exception:
              tmp_type = None
            if tmp_name and not tmp_name.startswith("sub_") and not tmp_name.startswith("nullsub_"):
              names_set.add(tmp_name)

          # String constants at data refs
          try:
            sdata = self.bv.get_string_at(dref)
            if sdata is not None:
              sval = sdata.value
              if isinstance(sval, bytes):
                sval = sval.decode("utf-8", "backslashreplace")
              if sval and sval not in constants:
                constants.append(sval)
          except Exception:
            pass

        # Immediate constants via LLIL
        try:
          llil = func.get_low_level_il_at(current_head)
          if llil is not None:
            self._walk_llil_for_constants(llil, constants)
        except Exception:
          pass

        ins_cmt1 = None
        ins_cmt2 = None
        try:
          c = func.get_comment_at(current_head) or self.bv.get_comment_at(current_head)
          if c:
            ins_cmt1 = c
        except Exception:
          pass

        operands_names = []  # BN doesn't really have "forced operand" text

        instructions_data.append(
          [
            rel_head,
            mnem,
            disasm,
            ins_cmt1,
            ins_cmt2,
            operands_names,
            tmp_name,
            tmp_type,
          ]
        )

        # Indirect-branch / switch detection
        try:
          ibs = func.get_indirect_branches_at(current_head)
          if ibs:
            targets = []
            for ib in ibs:
              try:
                targets.append(int(ib.dest_addr))
              except Exception:
                pass
            if targets:
              switches.append([len(targets), targets])
        except Exception:
          pass

      basic_blocks_data[block_ea] = instructions_data
      bb_relations[block_ea] = []
      if block_ea not in bb_degree:
        bb_degree[block_ea] = [0, 0]

      try:
        succs = [e.target for e in block.outgoing_edges]
      except Exception:
        succs = []
      try:
        preds = [e.source for e in block.incoming_edges]
      except Exception:
        preds = []

      for succ_block in succs:
        succ_base = int(succ_block.start) - image_base
        bb_relations[block_ea].append(succ_base)
        bb_degree[block_ea][1] += 1
        bb_edges.append((block_ea, succ_base))
        if succ_base not in bb_degree:
          bb_degree[succ_base] = [0, 0]
        bb_degree[succ_base][0] += 1
        edges += 1
        indegree += 1

      for pred_block in preds:
        pred_base = int(pred_block.start) - image_base
        try:
          bb_relations[pred_base].append(block_ea)
        except KeyError:
          bb_relations[pred_base] = [block_ea]
        edges += 1
        outdegree += 1

    # Second pass for topological relations.
    for block in blocks:
      block_ea = int(block.start) - image_base
      try:
        for edge in block.outgoing_edges:
          succ_base = int(edge.target.start) - image_base
          if block_ea in bb_topo_num and succ_base in bb_topo_num:
            bb_topological[bb_topo_num[block_ea]].append(bb_topo_num[succ_base])
      except Exception:
        pass

    topological_data = self.extract_function_topological_information(
      bb_relations, bb_topological
    )
    (
      bb_topological,
      bb_topological_sorted,
      strongly_connected,
      loops,
      strongly_connected_spp,
    ) = topological_data

    asm, assembly_addrs = self._build_assembly_text(assembly, f, image_base)
    try:
      clean_assembly = self.get_cmp_asm_lines(asm)
    except Exception:
      clean_assembly = ""

    cc = edges - nodes + 2
    proto = self._function_prototype(func)
    proto2 = proto
    try:
      prime = str(self.primes[cc])
    except Exception:
      prime = "0"

    comment = None
    try:
      comment = func.comment or None
    except Exception:
      comment = None

    bytes_hash_hex = md5(b"".join(bytes_hash_parts)).hexdigest() if bytes_hash_parts else md5(b"").hexdigest()
    function_hash_hex = md5(b"".join(function_hash_parts)).hexdigest() if function_hash_parts else md5(b"").hexdigest()

    function_flags = self._function_flags(func)

    # HLIL -> pseudo primes + a cheap textual pseudocode
    pseudocode_primes_int, pseudo, pseudo_list = self.get_pseudocode_primes(func)
    pseudo_lines = len(pseudo_list) if pseudo_list else 0
    pseudocode_primes = str(pseudocode_primes_int) if pseudocode_primes_int else None
    pseudo_hash1 = None
    pseudo_hash2 = None
    pseudo_hash3 = None
    if pseudo:
      try:
        h1, h2, h3 = self.kfh.hash_bytes(pseudo).split(";")
        pseudo_hash1 = h1 or None
        pseudo_hash2 = h2 or None
        pseudo_hash3 = h3 or None
      except Exception:
        pass

    # MLIL -> microcode replacement
    microcode_bblocks, microcode_bbrelations, microcode_spp = self.get_microcode(func)
    microcode_lines = self.microcode.get(f, [])
    microcode = "\n".join(microcode_lines) if microcode_lines else None
    try:
      clean_microcode = self.get_cmp_asm_lines(microcode) if microcode else None
    except Exception:
      clean_microcode = None

    clean_pseudo = self.get_cmp_pseudo_lines(pseudo) if pseudo else None

    md_index = self.extract_function_mdindex(
      bb_topological, bb_topological_sorted, bb_edges, bb_topo_num, bb_degree
    )

    try:
      seg = self.bv.get_sections_at(current_head)
      seg_rva = (current_head - int(seg[0].start)) if seg else (current_head - image_base)
    except Exception:
      seg_rva = current_head - image_base

    kgh_hash = self.calculate_kgh(func)
    rva = f - image_base

    names_list = sorted(names_set)

    export_time = str(time.monotonic() - export_time)

    props_list = (
      name,                         # 0
      nodes,                        # 1
      edges,                        # 2
      indegree,                     # 3
      outdegree,                    # 4
      size,                         # 5
      instructions,                 # 6
      mnems,                        # 7
      names_list,                   # 8
      proto,                        # 9
      cc,                           # 10
      prime,                        # 11
      f,                            # 12
      comment,                      # 13
      true_name,                    # 14
      bytes_hash_hex,               # 15
      pseudo,                       # 16
      pseudo_lines,                 # 17
      pseudo_hash1,                 # 18
      pseudocode_primes,            # 19
      function_flags,               # 20
      asm,                          # 21
      proto2,                       # 22
      pseudo_hash2,                 # 23
      pseudo_hash3,                 # 24
      len(strongly_connected) if strongly_connected else 0,  # 25
      loops,                        # 26
      rva,                          # 27
      bb_topological,               # 28
      strongly_connected_spp,       # 29
      clean_assembly,               # 30
      clean_pseudo,                 # 31
      mnemonics_spp,                # 32
      switches,                     # 33
      function_hash_hex,            # 34
      bytes_sum,                    # 35
      md_index,                     # 36
      constants,                    # 37
      len(constants),               # 38
      seg_rva,                      # 39
      assembly_addrs,               # 40
      kgh_hash,                     # 41
      None,                         # 42 source_file
      None,                         # 43 userdata
      microcode,                    # 44
      clean_microcode,              # 45
      microcode_spp,                # 46
      export_time,                  # 47
      microcode_bblocks,            # 48
      microcode_bbrelations,        # 49
      callers,                      # 50
      callees,                      # 51
      basic_blocks_data,            # 52
      bb_relations,                 # 53
    )

    if self.hooks is not None and "after_export_function" in dir(self.hooks):
      d = self.create_function_dictionary(props_list)
      d = self.hooks.after_export_function(d)
      props_list = self.get_function_from_dictionary(d)

    return props_list

  # ----------------------------------------------------------------------------
  def _walk_llil_for_constants(self, node, constants):
    """Walk LLIL, pull out constant immediates that pass the filter."""
    try:
      op = getattr(node, "operation", None)
      op_name = getattr(op, "name", "") if op is not None else ""
    except Exception:
      op_name = ""
    if "CONST" in op_name:
      try:
        val = int(getattr(node, "constant", 0))
        if _constant_filter(val) and val not in constants:
          constants.append(val)
      except Exception:
        pass
    try:
      for sub in getattr(node, "operands", []) or []:
        if hasattr(sub, "operation"):
          self._walk_llil_for_constants(sub, constants)
    except Exception:
      pass

  # ----------------------------------------------------------------------------
  def _build_assembly_text(self, assembly, f, image_base):
    asm = []
    keys = sorted(assembly.keys())
    assembly_addrs = []
    base = f - image_base
    if base in keys:
      keys.remove(base)
    keys.insert(0, base)
    for key in keys:
      if key not in assembly:
        continue
      for line in assembly[key]:
        assembly_addrs.append(line[0])
        asm.append(line[1])
    return "\n".join(asm), assembly_addrs

  # ----------------------------------------------------------------------------
  def commit_and_start_transaction(self):
    try:
      self.db.execute("commit")
    except sqlite3.OperationalError:
      pass
    if config.SQLITE_PRAGMA_SYNCHRONOUS is not None:
      self.db.execute(f"PRAGMA synchronous = {config.SQLITE_PRAGMA_SYNCHRONOUS}")
    if config.SQLITE_JOURNAL_MODE is not None:
      self.db.execute(f"PRAGMA journal_mode = {config.SQLITE_JOURNAL_MODE}")
    self.db.execute("BEGIN transaction")

  # ----------------------------------------------------------------------------
  def save_callgraph(self, primes, all_primes, md5sum):
    cur = self.db_cursor()
    try:
      proc = "unknown"
      if self.bv is not None:
        try:
          proc = self.bv.arch.name
        except Exception:
          pass
      sql = "insert into main.program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (?, ?, ?, ?)"
      cur.execute(sql, (primes, all_primes, proc, md5sum))
    finally:
      cur.close()

  # ----------------------------------------------------------------------------
  def do_export(self, crashed_before=False):
    callgraph_primes = 1
    callgraph_all_primes = {}
    log("Exporting range 0x%08x - 0x%08x" % (self.min_ea, self.max_ea))

    func_list = []
    for func in self.bv.functions:
      ea = int(func.start)
      if ea < self.min_ea or ea >= self.max_ea:
        continue
      func_list.append(func)

    total_funcs = len(func_list)
    t = time.monotonic()
    self.commit_and_start_transaction()

    i = 0
    self._funcs_cache = {}
    for func in func_list:
      i += 1
      if (total_funcs >= 100) and i % max(1, int(total_funcs / 100)) == 0 or i == 1:
        if config.COMMIT_AFTER_EACH_GUI_UPDATE:
          self.commit_and_start_transaction()
        elapsed = time.monotonic() - t
        log(f"Exported {i}/{total_funcs} ({100*i/total_funcs:.1f}%, {elapsed:.1f}s)")

      # Skip externs
      try:
        sym = func.symbol
        if sym is not None and sym.type in (
          SymbolType.ExternalSymbol,
          SymbolType.ImportedFunctionSymbol,
        ):
          continue
      except Exception:
        pass

      props = self.read_function(func)
      self.clear_pseudo_fields()
      if props is False:
        continue

      ret = props[11]
      try:
        callgraph_primes *= decimal.Decimal(ret)
      except Exception:
        pass
      try:
        callgraph_all_primes[ret] += 1
      except KeyError:
        callgraph_all_primes[ret] = 1

      try:
        self.save_function(props)
      except Exception:
        log(f"Error saving function {props[0]}: {sys.exc_info()[1]}")
        traceback.print_exc()

      if total_funcs > config.EXPORTING_FUNCTIONS_TO_COMMIT:
        if i % max(1, int(total_funcs / 10)) == 0:
          self.commit_and_start_transaction()

    self.commit_and_start_transaction()

    md5sum = ""
    try:
      fn = self.bv.file.filename
      if fn and os.path.exists(fn):
        with open(fn, "rb") as fp:
          md5sum = md5(fp.read()).hexdigest()
    except Exception:
      pass

    self.save_callgraph(
      str(callgraph_primes), json.dumps(callgraph_all_primes), md5sum
    )

    log_refresh("Creating indices...")
    self.create_indices()

  # ----------------------------------------------------------------------------
  def export(self):
    if self.project_script is not None:
      if not self.load_hooks():
        return False
    try:
      self.do_export()
    except Exception:
      log(f"Error: {sys.exc_info()[1]}")
      traceback.print_exc()
    self.db.commit()
    cur = self.db_cursor()
    try:
      cur.execute("analyze")
    finally:
      cur.close()
    self.db_close()
    return True


def run_diff(db1, db2, out_db):
  """
  Run a Diaphora diff between two already-exported SQLite databases and save
  the results to @out_db. Headless-friendly (no Binary Ninja UI required).

  Returns the output DB path on success.
  """
  bd = CBinjaBinDiff(None, db1)
  bd.diff(db2)
  if out_db is not None:
    bd.save_results(out_db)
  return out_db

# ============================================================
# UI (merged from diaphora_binja_ui.py — BN UI process only)
# ============================================================

import sqlite3
import difflib
from typing import List, Dict, Optional

try:
  from binaryninjaui import (
    Sidebar,
    SidebarWidget,
    SidebarWidgetType,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    UIContext,
  )
  HAS_BNUI = True
except Exception:  # pragma: no cover
  HAS_BNUI = False
  SidebarWidget = object  # type: ignore
  SidebarWidgetType = object  # type: ignore

try:
  from PySide6.QtCore import (
    Qt,
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Signal,
    QObject,
  )
  from PySide6.QtGui import (
    QColor,
    QTextCharFormat,
    QTextCursor,
    QFont,
    QAction,
    QKeySequence,
  )
  from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QTableView,
    QHeaderView,
    QAbstractItemView,
    QApplication,
    QDialog,
    QPlainTextEdit,
    QLabel,
    QPushButton,
    QMenu,
    QMessageBox,
    QShortcut,
    QSplitter,
  )
  HAS_QT = True
except Exception:  # pragma: no cover
  HAS_QT = False

try:
  import binaryninja
  from binaryninja import BackgroundTaskThread
  HAS_BN = True
except Exception:  # pragma: no cover
  HAS_BN = False
  BackgroundTaskThread = object  # type: ignore


# ---------------------------------------------------------------------------
# Results DB access
# ---------------------------------------------------------------------------

RESULT_CATEGORIES = [
  ("best", "Best"),
  ("partial", "Partial"),
  ("unreliable", "Unreliable"),
  ("multimatch", "Multimatches"),
  ("primary", "Unmatched primary"),
  ("secondary", "Unmatched secondary"),
]

MATCH_COLS = [
  "line", "address", "name", "address2", "name2",
  "ratio", "nodes1", "nodes2", "description",
]
UNMATCHED_COLS = ["line", "address", "name"]


def load_results(db_path: str) -> Dict[str, List[dict]]:
  """Return a dict mapping category -> list of row dicts."""
  out: Dict[str, List[dict]] = {c: [] for c, _ in RESULT_CATEGORIES}
  if not db_path or not os.path.exists(db_path):
    return out
  con = sqlite3.connect(db_path)
  try:
    cur = con.cursor()
    try:
      cur.execute(
        "select type, line, address, name, address2, name2, ratio, "
        "nodes1, nodes2, description from results"
      )
      for row in cur.fetchall():
        ctype = row[0]
        if ctype not in out:
          continue
        out[ctype].append({
          "line": row[1],
          "address": row[2],
          "name": row[3],
          "address2": row[4],
          "name2": row[5],
          "ratio": row[6],
          "nodes1": row[7],
          "nodes2": row[8],
          "description": row[9],
        })
    except sqlite3.Error:
      pass
    try:
      cur.execute("select type, line, address, name from unmatched")
      for row in cur.fetchall():
        ctype = row[0]
        if ctype not in out:
          continue
        out[ctype].append({
          "line": row[1],
          "address": row[2],
          "name": row[3],
        })
    except sqlite3.Error:
      pass
  finally:
    con.close()
  return out


def load_config(db_path: str) -> Dict[str, str]:
  info = {"main_db": "", "diff_db": "", "version": "", "date": ""}
  if not db_path or not os.path.exists(db_path):
    return info
  try:
    con = sqlite3.connect(db_path)
    try:
      cur = con.cursor()
      cur.execute("select main_db, diff_db, version, date from config")
      row = cur.fetchone()
      if row:
        info["main_db"] = row[0] or ""
        info["diff_db"] = row[1] or ""
        info["version"] = row[2] or ""
        info["date"] = row[3] or ""
    finally:
      con.close()
  except Exception:
    pass
  return info


def _parse_addr(val) -> Optional[int]:
  if val is None:
    return None
  try:
    if isinstance(val, int):
      return val
    s = str(val).strip()
    if not s:
      return None
    if s.lower().startswith("0x"):
      return int(s, 16)
    return int(s)
  except Exception:
    try:
      return int(str(val), 16)
    except Exception:
      return None


# ---------------------------------------------------------------------------
# Table model
# ---------------------------------------------------------------------------

if HAS_QT:

  class DiffResultsModel(QAbstractTableModel):
    MATCH_HEADERS = [
      "Line", "Address", "Name", "Address 2", "Name 2",
      "Ratio", "BBs 1", "BBs 2", "Description",
    ]
    UNMATCHED_HEADERS = ["Line", "Address", "Name"]

    def __init__(self, rows: List[dict], unmatched: bool = False, parent=None):
      super().__init__(parent)
      self.rows = list(rows)
      self.unmatched = unmatched
      self.headers = (
        self.UNMATCHED_HEADERS if unmatched else self.MATCH_HEADERS
      )
      self.keys = UNMATCHED_COLS if unmatched else MATCH_COLS

    def rowCount(self, parent=QModelIndex()):
      if parent.isValid():
        return 0
      return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
      if parent.isValid():
        return 0
      return len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
      if role != Qt.DisplayRole:
        return None
      if orientation == Qt.Horizontal and 0 <= section < len(self.headers):
        return self.headers[section]
      return None

    def data(self, index, role=Qt.DisplayRole):
      if not index.isValid():
        return None
      row = self.rows[index.row()]
      key = self.keys[index.column()]
      val = row.get(key, "")
      if role == Qt.DisplayRole or role == Qt.EditRole:
        if key == "ratio" and val not in ("", None):
          try:
            return f"{float(val):.3f}"
          except Exception:
            return str(val)
        return "" if val is None else str(val)
      if role == Qt.TextAlignmentRole:
        if key in ("ratio", "nodes1", "nodes2", "line"):
          return int(Qt.AlignRight | Qt.AlignVCenter)
      if role == Qt.UserRole:
        return row
      return None

    def row_dict(self, row_index: int) -> Optional[dict]:
      if 0 <= row_index < len(self.rows):
        return self.rows[row_index]
      return None

  # -------------------------------------------------------------------------
  # Diff dialogs
  # -------------------------------------------------------------------------

  class _SideBySideDiffDialog(QDialog):
    def __init__(self, title: str, left_text: str, right_text: str,
                 left_label: str = "Primary", right_label: str = "Secondary",
                 parent=None):
      super().__init__(parent)
      self.setWindowTitle(title)
      self.resize(1100, 700)

      layout = QVBoxLayout(self)
      splitter = QSplitter(Qt.Horizontal)
      layout.addWidget(splitter, 1)

      def mk(label_text: str) -> (QWidget, QPlainTextEdit):
        box = QWidget()
        vb = QVBoxLayout(box)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.addWidget(QLabel(label_text))
        te = QPlainTextEdit()
        te.setReadOnly(True)
        f = QFont("Menlo")
        f.setStyleHint(QFont.Monospace)
        te.setFont(f)
        vb.addWidget(te, 1)
        return box, te

      lbox, self.left = mk(left_label)
      rbox, self.right = mk(right_label)
      splitter.addWidget(lbox)
      splitter.addWidget(rbox)

      self.left.setPlainText(left_text or "")
      self.right.setPlainText(right_text or "")

      self._highlight(left_text or "", right_text or "")

      close_row = QHBoxLayout()
      close_row.addStretch(1)
      btn = QPushButton("Close")
      btn.clicked.connect(self.accept)
      close_row.addWidget(btn)
      layout.addLayout(close_row)

    def _highlight(self, left_text: str, right_text: str):
      left_lines = left_text.splitlines()
      right_lines = right_text.splitlines()
      matcher = difflib.SequenceMatcher(a=left_lines, b=right_lines)

      equal_fmt = QTextCharFormat()
      del_fmt = QTextCharFormat()
      del_fmt.setBackground(QColor(90, 30, 30))
      ins_fmt = QTextCharFormat()
      ins_fmt.setBackground(QColor(30, 70, 30))
      repl_fmt = QTextCharFormat()
      repl_fmt.setBackground(QColor(90, 70, 20))

      def apply(te: QPlainTextEdit, start: int, end: int, fmt: QTextCharFormat):
        doc = te.document()
        for i in range(start, end):
          block = doc.findBlockByNumber(i)
          if not block.isValid():
            continue
          cur = QTextCursor(block)
          cur.select(QTextCursor.LineUnderCursor)
          cur.mergeCharFormat(fmt)

      for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
          continue
        elif tag == "delete":
          apply(self.left, i1, i2, del_fmt)
        elif tag == "insert":
          apply(self.right, j1, j2, ins_fmt)
        elif tag == "replace":
          apply(self.left, i1, i2, repl_fmt)
          apply(self.right, j1, j2, repl_fmt)


  # -------------------------------------------------------------------------
  # Text extraction helpers (BN side + other DB side)
  # -------------------------------------------------------------------------

  def _bv_func_at(bv, addr: int):
    if bv is None or addr is None:
      return None
    try:
      funcs = bv.get_functions_containing(addr)
      if funcs:
        return funcs[0]
      return bv.get_function_at(addr)
    except Exception:
      return None

  def _bv_asm_text(bv, addr: int) -> str:
    func = _bv_func_at(bv, addr)
    if func is None:
      return f"; no function at 0x{addr:x}\n" if addr is not None else ""
    lines = []
    try:
      for block in func.basic_blocks:
        lines.append(f"; block 0x{block.start:x}")
        for line in block.get_disassembly_text():
          lines.append(f"0x{line.address:x}  {line}")
        lines.append("")
    except Exception:
      lines.append(f"; error disassembling: {traceback.format_exc()}")
    return "\n".join(lines)

  def _bv_hlil_text(bv, addr: int) -> str:
    func = _bv_func_at(bv, addr)
    if func is None:
      return ""
    try:
      hlil = func.hlil
      if hlil is None:
        return ""
      out = []
      for ins in hlil.instructions:
        out.append(str(ins))
      return "\n".join(out)
    except Exception:
      return f"; error decompiling: {traceback.format_exc()}"

  def _db_function_asm(db_path: str, addr: int) -> str:
    """Reconstruct an asm-ish listing from a Diaphora export DB."""
    if not db_path or not os.path.exists(db_path) or addr is None:
      return ""
    try:
      con = sqlite3.connect(db_path)
      try:
        cur = con.cursor()
        cur.execute(
          "select id, name, assembly from functions where address = ?",
          (str(addr),),
        )
        row = cur.fetchone()
        if row is None:
          return f"; no function at 0x{addr:x} in {os.path.basename(db_path)}\n"
        _fid, name, assembly = row
        header = f"; {name} @ 0x{addr:x}\n"
        return header + (assembly or "")
      finally:
        con.close()
    except Exception:
      return f"; error reading {db_path}: {traceback.format_exc()}"

  def _db_function_pseudo(db_path: str, addr: int) -> str:
    if not db_path or not os.path.exists(db_path) or addr is None:
      return ""
    try:
      con = sqlite3.connect(db_path)
      try:
        cur = con.cursor()
        cur.execute(
          "select name, pseudocode from functions where address = ?",
          (str(addr),),
        )
        row = cur.fetchone()
        if row is None:
          return ""
        name, pseudo = row
        return f"// {name} @ 0x{addr:x}\n{pseudo or ''}"
      finally:
        con.close()
    except Exception:
      return ""

  # -------------------------------------------------------------------------
  # Sidebar widget
  # -------------------------------------------------------------------------

  class DiaphoraSidebarWidget(SidebarWidget):
    def __init__(self, name: str = "Diaphora"):
      super().__init__(name)
      self._bv = None
      self._results_db: Optional[str] = None
      self._cfg: Dict[str, str] = {}
      self._tables: Dict[str, QTableView] = {}
      self._models: Dict[str, DiffResultsModel] = {}

      root = QVBoxLayout(self)
      root.setContentsMargins(4, 4, 4, 4)

      self.status_label = QLabel("No Diaphora results loaded.")
      self.status_label.setWordWrap(True)
      root.addWidget(self.status_label)

      btn_row = QHBoxLayout()
      self.reload_btn = QPushButton("Reload")
      self.reload_btn.clicked.connect(self.reload)
      btn_row.addWidget(self.reload_btn)
      btn_row.addStretch(1)
      root.addLayout(btn_row)

      self.tabs = QTabWidget()
      root.addWidget(self.tabs, 1)

      for key, title in RESULT_CATEGORIES:
        view = QTableView()
        view.setSortingEnabled(True)
        view.setSelectionBehavior(QAbstractItemView.SelectRows)
        view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        view.horizontalHeader().setStretchLastSection(True)
        view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        view.setContextMenuPolicy(Qt.CustomContextMenu)
        view.customContextMenuRequested.connect(
          lambda pos, k=key: self._on_context_menu(k, pos)
        )
        view.doubleClicked.connect(
          lambda idx, k=key: self._on_double_click(k, idx)
        )
        shortcut = QShortcut(QKeySequence.Copy, view)
        shortcut.setContext(Qt.WidgetShortcut)
        shortcut.activated.connect(lambda k=key: self._copy_selected_rows(k))
        self.tabs.addTab(view, title)
        self._tables[key] = view

    # ---- public API --------------------------------------------------------

    def set_binary_view(self, bv):
      self._bv = bv

    def set_results_db(self, db_path: Optional[str]):
      self._results_db = db_path
      self.reload()

    def results_db(self) -> Optional[str]:
      return self._results_db

    def reload(self):
      data = load_results(self._results_db) if self._results_db else {
        c: [] for c, _ in RESULT_CATEGORIES
      }
      self._cfg = load_config(self._results_db) if self._results_db else {}
      total = 0
      for i, (key, title) in enumerate(RESULT_CATEGORIES):
        rows = data.get(key, [])
        unmatched = key in ("primary", "secondary")
        model = DiffResultsModel(rows, unmatched=unmatched)
        proxy = QSortFilterProxyModel()
        proxy.setSourceModel(model)
        view = self._tables[key]
        view.setModel(proxy)
        view.resizeColumnsToContents()
        self._models[key] = model
        count = len(rows)
        total += count
        self.tabs.setTabText(i, f"{title} ({count})")
      if self._results_db:
        self.status_label.setText(
          f"{os.path.basename(self._results_db)}\n"
          f"main: {os.path.basename(self._cfg.get('main_db',''))}  "
          f"diff: {os.path.basename(self._cfg.get('diff_db',''))}\n"
          f"{total} rows total"
        )
      else:
        self.status_label.setText("No Diaphora results loaded.")

    # ---- BN sidebar hooks --------------------------------------------------

    def notifyViewChanged(self, view_frame):  # noqa: N802 (BN API)
      try:
        if view_frame is None:
          return
        view = view_frame.getCurrentViewInterface()
        if view is not None:
          bv = view.getData()
          if bv is not None:
            self._bv = bv
      except Exception:
        pass

    # ---- helpers -----------------------------------------------------------

    def _selected_row(self, key: str) -> Optional[dict]:
      view = self._tables.get(key)
      if view is None:
        return None
      idx = view.currentIndex()
      if not idx.isValid():
        return None
      proxy = view.model()
      src = proxy.mapToSource(idx) if isinstance(proxy, QSortFilterProxyModel) else idx
      model = self._models.get(key)
      if model is None:
        return None
      return model.row_dict(src.row())

    def _on_double_click(self, key: str, idx):
      if not idx.isValid():
        return
      proxy = self._tables[key].model()
      src = proxy.mapToSource(idx) if isinstance(proxy, QSortFilterProxyModel) else idx
      row = self._models[key].row_dict(src.row())
      if row is None:
        return
      addr = _parse_addr(row.get("address"))
      if addr is None:
        return
      self._navigate(addr)

    def _navigate(self, addr: int):
      try:
        ctx = UIContext.activeContext() if HAS_BNUI else None
        if ctx is not None:
          vf = ctx.getCurrentViewFrame()
          if vf is not None:
            for vname in ("Linear:", "Graph:"):
              try:
                if vf.navigate(vname, addr):
                  return
              except Exception:
                pass
      except Exception:
        pass
      try:
        if self._bv is not None:
          self._bv.navigate(self._bv.view, addr)
      except Exception:
        pass

    # ---- context menu ------------------------------------------------------

    def _copy_selected_rows(self, key: str):
      view = self._tables.get(key)
      if view is None:
        return
      proxy = view.model()
      indexes = view.selectionModel().selectedRows()
      if not indexes:
        return
      cols = UNMATCHED_COLS if key in ("primary", "secondary") else MATCH_COLS
      header = "\t".join(c for c in cols if c != "line")
      lines = [header]
      for idx in sorted(indexes, key=lambda i: i.row()):
        src = proxy.mapToSource(idx) if hasattr(proxy, "mapToSource") else idx
        model = proxy.sourceModel() if hasattr(proxy, "sourceModel") else proxy
        row_data = model.rows[src.row()] if hasattr(model, "rows") else {}
        lines.append("\t".join(str(row_data.get(c, "")) for c in cols if c != "line"))
      QApplication.clipboard().setText("\n".join(lines))

    def _on_context_menu(self, key: str, pos):
      view = self._tables.get(key)
      if view is None:
        return
      row = self._selected_row(key)
      menu = QMenu(view)

      unmatched = key in ("primary", "secondary")

      act_copy_row = QAction("Copy row(s)\tCtrl+C", menu)
      act_copy_row.triggered.connect(lambda: self._copy_selected_rows(key))
      menu.addAction(act_copy_row)

      if row:
        act_copy_name = QAction(f"Copy name: {row.get('name', '')}", menu)
        act_copy_name.triggered.connect(
          lambda: QApplication.clipboard().setText(row.get("name", ""))
        )
        menu.addAction(act_copy_name)

      menu.addSeparator()

      act_goto = QAction("Navigate to address", menu)
      act_goto.triggered.connect(lambda: self._action_navigate(key))
      menu.addAction(act_goto)

      if not unmatched:
        menu.addSeparator()
        a1 = QAction("Show asm diff", menu)
        a1.triggered.connect(lambda: self._action_asm_diff(key))
        menu.addAction(a1)

        a2 = QAction("Show pseudo diff", menu)
        a2.triggered.connect(lambda: self._action_pseudo_diff(key))
        menu.addAction(a2)

        a3 = QAction("Show CFG diff", menu)
        a3.triggered.connect(lambda: self._action_cfg_diff(key))
        menu.addAction(a3)

        menu.addSeparator()
        a4 = QAction("Import name", menu)
        a4.triggered.connect(lambda: self._action_import_name(key))
        menu.addAction(a4)

        a5 = QAction("Import all from this category", menu)
        a5.triggered.connect(lambda: self._action_import_all(key))
        menu.addAction(a5)

      menu.exec_(view.viewport().mapToGlobal(pos))

    def _action_navigate(self, key: str):
      row = self._selected_row(key)
      if row is None:
        return
      addr = _parse_addr(row.get("address"))
      if addr is not None:
        self._navigate(addr)

    def _action_asm_diff(self, key: str):
      row = self._selected_row(key)
      if row is None:
        return
      a1 = _parse_addr(row.get("address"))
      a2 = _parse_addr(row.get("address2"))
      left = _bv_asm_text(self._bv, a1)
      right = _db_function_asm(self._cfg.get("diff_db", ""), a2)
      title = f"Asm diff: {row.get('name','')} vs {row.get('name2','')}"
      dlg = _SideBySideDiffDialog(title, left, right,
                                  left_label=row.get("name", "primary"),
                                  right_label=row.get("name2", "secondary"))
      dlg.exec_()

    def _action_pseudo_diff(self, key: str):
      row = self._selected_row(key)
      if row is None:
        return
      a1 = _parse_addr(row.get("address"))
      a2 = _parse_addr(row.get("address2"))
      left = _bv_hlil_text(self._bv, a1)
      if not left:
        left = _db_function_pseudo(self._cfg.get("main_db", ""), a1)
      right = _db_function_pseudo(self._cfg.get("diff_db", ""), a2)
      title = f"Pseudo diff: {row.get('name','')} vs {row.get('name2','')}"
      dlg = _SideBySideDiffDialog(title, left, right,
                                  left_label=row.get("name", "primary"),
                                  right_label=row.get("name2", "secondary"))
      dlg.exec_()

    def _action_cfg_diff(self, key: str):
      row = self._selected_row(key)
      if row is None:
        return
      # Minimal implementation: show a textual BB summary side-by-side.
      # A proper FlowGraphWidget embedding is a TODO (see module docstring).
      a1 = _parse_addr(row.get("address"))
      a2 = _parse_addr(row.get("address2"))
      left = self._cfg_text_bn(a1)
      right = self._cfg_text_db(self._cfg.get("diff_db", ""), a2)
      title = f"CFG diff: {row.get('name','')} vs {row.get('name2','')}"
      dlg = _SideBySideDiffDialog(title, left, right,
                                  left_label=row.get("name", "primary"),
                                  right_label=row.get("name2", "secondary"))
      dlg.exec_()

    def _cfg_text_bn(self, addr: Optional[int]) -> str:
      func = _bv_func_at(self._bv, addr)
      if func is None:
        return ""
      lines = []
      try:
        for bb in func.basic_blocks:
          succs = ",".join(f"0x{e.target.start:x}" for e in bb.outgoing_edges)
          lines.append(f"bb 0x{bb.start:x}-0x{bb.end:x} -> [{succs}]")
      except Exception:
        pass
      return "\n".join(lines)

    def _cfg_text_db(self, db_path: str, addr: Optional[int]) -> str:
      if not db_path or not os.path.exists(db_path) or addr is None:
        return ""
      try:
        con = sqlite3.connect(db_path)
        try:
          cur = con.cursor()
          cur.execute(
            "select bb_relations, nodes, edges from functions where address = ?",
            (str(addr),),
          )
          row = cur.fetchone()
          if not row:
            return ""
          rels, nodes, edges = row
          return f"nodes={nodes} edges={edges}\n{rels or ''}"
        finally:
          con.close()
      except Exception:
        return ""

    def _action_import_name(self, key: str):
      row = self._selected_row(key)
      if row is None or self._bv is None:
        return
      addr = _parse_addr(row.get("address"))
      new_name = row.get("name2") or ""
      if addr is None or not new_name:
        return
      func = _bv_func_at(self._bv, addr)
      if func is None:
        QMessageBox.warning(self, "Diaphora",
                            f"No function at 0x{addr:x}")
        return
      try:
        func.name = new_name
      except Exception as exc:
        QMessageBox.warning(self, "Diaphora", f"Rename failed: {exc}")

    def _action_import_all(self, key: str):
      model = self._models.get(key)
      if model is None or self._bv is None:
        return
      count = 0
      for row in model.rows:
        addr = _parse_addr(row.get("address"))
        new_name = row.get("name2") or ""
        if addr is None or not new_name:
          continue
        func = _bv_func_at(self._bv, addr)
        if func is None:
          continue
        try:
          func.name = new_name
          count += 1
        except Exception:
          pass
      QMessageBox.information(self, "Diaphora",
                              f"Imported {count} names from {key}.")


  # -------------------------------------------------------------------------
  # Sidebar type registration
  # -------------------------------------------------------------------------

  _SIDEBAR_SINGLETON: Optional[DiaphoraSidebarWidget] = None

  if HAS_BNUI:

    class DiaphoraSidebarWidgetType(SidebarWidgetType):
      def __init__(self):
        # 24x24 placeholder icon - a simple "D"
        from PySide6.QtGui import QImage, QPainter
        img = QImage(24, 24, QImage.Format_RGB32)
        img.fill(QColor(40, 40, 40))
        p = QPainter(img)
        p.setPen(QColor(220, 220, 220))
        f = QFont()
        f.setBold(True)
        f.setPointSize(14)
        p.setFont(f)
        p.drawText(img.rect(), Qt.AlignCenter, "D")
        p.end()
        super().__init__(img, "Diaphora")

      def createWidget(self, frame, data):  # noqa: N802
        global _SIDEBAR_SINGLETON
        w = DiaphoraSidebarWidget("Diaphora")
        _SIDEBAR_SINGLETON = w
        try:
          if data is not None:
            w.set_binary_view(data)
        except Exception:
          pass
        return w

      def defaultLocation(self):  # noqa: N802
        try:
          return SidebarWidgetLocation.RightContent
        except Exception:
          return 0

      def contextSensitivity(self):  # noqa: N802
        try:
          return SidebarContextSensitivity.SelfManagedSidebarContext
        except Exception:
          return 0


# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------

if HAS_BN:

  class ExportTask(BackgroundTaskThread):
    def __init__(self, bv, out_db: str, on_done=None):
      super().__init__("Diaphora: exporting BinaryView...", True)
      self.bv = bv
      self.out_db = out_db
      self._on_done = on_done

    def run(self):
      try:
        from diaphora_binja import CBinjaBinDiff
        if os.path.exists(self.out_db):
          try:
            os.remove(self.out_db)
          except Exception:
            pass
        bd = CBinjaBinDiff(self.bv, self.out_db)
        bd.export()
      except Exception:
        traceback.print_exc()
      finally:
        try:
          if self._on_done is not None:
            self._on_done(self.out_db)
        except Exception:
          traceback.print_exc()

  class DiffTask(BackgroundTaskThread):
    def __init__(self, db1: str, db2: str, out_db: str, on_done=None):
      super().__init__("Diaphora: diffing databases...", True)
      self.db1 = db1
      self.db2 = db2
      self.out_db = out_db
      self._on_done = on_done

    def run(self):
      try:
        from diaphora_binja import run_diff
        run_diff(self.db1, self.db2, self.out_db)
      except Exception:
        traceback.print_exc()
      finally:
        try:
          if self._on_done is not None:
            self._on_done(self.out_db)
        except Exception:
          traceback.print_exc()

  class ExportAndDiffTask(BackgroundTaskThread):
    def __init__(self, bv, tmp_db: str, other_db: str, out_db: str, on_done=None):
      super().__init__("Diaphora: export + diff...", True)
      self.bv = bv
      self.tmp_db = tmp_db
      self.other_db = other_db
      self.out_db = out_db
      self._on_done = on_done

    def run(self):
      try:
        from diaphora_binja import CBinjaBinDiff, run_diff
        if os.path.exists(self.tmp_db):
          try:
            os.remove(self.tmp_db)
          except Exception:
            pass
        bd = CBinjaBinDiff(self.bv, self.tmp_db)
        bd.export()
        run_diff(self.tmp_db, self.other_db, self.out_db)
      except Exception:
        traceback.print_exc()
      finally:
        try:
          if self._on_done is not None:
            self._on_done(self.out_db)
        except Exception:
          traceback.print_exc()


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------

_SIDEBAR_TYPE_REGISTERED = False


def register_sidebar():
  """Register the Diaphora sidebar widget type with Binary Ninja."""
  global _SIDEBAR_TYPE_REGISTERED
  if _SIDEBAR_TYPE_REGISTERED or not HAS_BNUI or not HAS_QT:
    return
  try:
    Sidebar.addSidebarWidgetType(DiaphoraSidebarWidgetType())
    _SIDEBAR_TYPE_REGISTERED = True
  except Exception:
    traceback.print_exc()


def get_sidebar_singleton():
  return _SIDEBAR_SINGLETON if HAS_QT else None
