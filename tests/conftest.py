"""
Direct In-Memory GenVM Test Harness for SemanticFirewall.
Provides VM simulation, accounts, LLM mocking, and strict_eq consensus.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import types
import re
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
import pytest


# ─────────────────────────────────────────────────────────────
# 1. GenLayer Native Types Simulation
# ─────────────────────────────────────────────────────────────

class Address(str):
    def __new__(cls, val):
        if isinstance(val, bytes):
            return super().__new__(cls, "0x" + val.hex())
        val_str = str(val)
        if not val_str.startswith("0x"):
            val_str = "0x" + val_str
        return super().__new__(cls, val_str)


class u256(int):
    def __new__(cls, val=0):
        v = int(val)
        if v < 0 or v >= 2**256:
            raise ValueError(f"u256 overflow: {v}")
        return super().__new__(cls, v)


class u64(int):
    def __new__(cls, val=0):
        v = int(val)
        if v < 0 or v >= 2**64:
            raise ValueError(f"u64 overflow: {v}")
        return super().__new__(cls, v)


class u32(int):
    def __new__(cls, val=0):
        v = int(val)
        if v < 0 or v >= 2**32:
            raise ValueError(f"u32 overflow: {v}")
        return super().__new__(cls, v)


class TreeMap(dict):
    pass


def allow_storage(cls):
    return cls


class UserError(Exception):
    pass


# ─────────────────────────────────────────────────────────────
# 2. Virtual Machine Context & Mock Engine
# ─────────────────────────────────────────────────────────────

class VMContext:
    def __init__(self):
        self.sender_address = Address("0x1111111111111111111111111111111111111111")
        self.value = u256(0)
        self.web_mocks: Dict[str, Any] = {}
        self.llm_mocks: Dict[str, Any] = {}
        self.transfers = []
        self.simulate_disagreement = False

    @property
    def sender(self) -> Address:
        return self.sender_address

    @sender.setter
    def sender(self, val: Any):
        self.sender_address = Address(val)

    def clear(self):
        self.web_mocks.clear()
        self.llm_mocks.clear()
        self.transfers.clear()
        self.simulate_disagreement = False

    def mock_web(self, pattern: str, response: Any):
        self.web_mocks[pattern] = response

    def mock_llm(self, pattern: str, response: Any):
        self.llm_mocks[pattern] = response

    def render_web(self, url: str, mode: str = "text") -> str:
        for pat, resp in self.web_mocks.items():
            if re.search(pat, url):
                return str(resp)
        return "Generic mock vulnerability PoC evidence"

    def exec_prompt(self, prompt: str, response_format: str = "json") -> Any:
        for pat, resp in self.llm_mocks.items():
            if re.search(pat, prompt, re.DOTALL):
                return resp

        # Smart contextual default
        if "prompt injection" in prompt.lower() or "firewall" in prompt.lower() or "is_safe" in prompt.lower():
            return json.dumps({
                "is_safe": True,
                "verdict": "PERMIT",
                "threat_category": "NONE",
                "reason": "Authorized benign execution."
            })
        else:
            return json.dumps({
                "in_scope": True,
                "verified_severity": 4,
                "reasoning": "Valid PoC exploit confirmed."
            })

    def strict_eq(self, fn: Callable[[], Any]) -> Any:
        if self.simulate_disagreement:
            raise Exception("Consensus equivalence failure (validator disagreement)")
        return fn()

    def send(self, recipient: Address, amount: u256):
        self.transfers.append((recipient, amount))


if "_gl_test_vm_shared" in sys.modules:
    _CURRENT_VM = sys.modules["_gl_test_vm_shared"]
else:
    _CURRENT_VM = VMContext()
    sys.modules["_gl_test_vm_shared"] = _CURRENT_VM


# ─────────────────────────────────────────────────────────────
# 3. Dynamic GenLayer Module Registration
# ─────────────────────────────────────────────────────────────

def _ensure_genlayer_module():
    if "genlayer" in sys.modules:
        return sys.modules["genlayer"]

    gl_mod = types.ModuleType("genlayer")

    class Contract:
        def __new__(cls, *args, **kwargs):
            instance = super().__new__(cls)
            for attr_name, attr_type in getattr(cls, "__annotations__", {}).items():
                if "TreeMap" in str(attr_type):
                    setattr(instance, attr_name, TreeMap())
            return instance

    class _WriteDecorator:
        def __call__(self, fn):
            return fn

        def payable(self, fn):
            return fn

    class PublicNamespace:
        write = _WriteDecorator()

        @staticmethod
        def view(fn):
            return fn

    class WebNamespace:
        @staticmethod
        def render(url: str, mode: str = "text") -> str:
            return _CURRENT_VM.render_web(url, mode)

    class NondetNamespace:
        web = WebNamespace()

        @staticmethod
        def exec_prompt(prompt: str, response_format: str = "json") -> Any:
            return _CURRENT_VM.exec_prompt(prompt, response_format)

    class EqPrincipleNamespace:
        @staticmethod
        def strict_eq(fn: Callable[[], Any]) -> Any:
            return _CURRENT_VM.strict_eq(fn)

    class MessageProxy:
        @property
        def sender(self):
            return _CURRENT_VM.sender

        @property
        def value(self):
            return _CURRENT_VM.value

        @staticmethod
        def send(recipient: Address, amount: u256):
            _CURRENT_VM.send(recipient, amount)

    gl_mod.Contract = Contract
    gl_mod.public = PublicNamespace()
    gl_mod.Address = Address
    gl_mod.u256 = u256
    gl_mod.u64 = u64
    gl_mod.u32 = u32
    gl_mod.TreeMap = TreeMap
    gl_mod.allow_storage = allow_storage
    gl_mod.UserError = UserError

    gl_mod.nondet = NondetNamespace()
    gl_mod.eq_principle = EqPrincipleNamespace()
    gl_mod.message = MessageProxy()

    gl_object = types.SimpleNamespace(
        Contract=Contract,
        public=gl_mod.public,
        nondet=gl_mod.nondet,
        eq_principle=gl_mod.eq_principle,
        message=gl_mod.message,
        UserError=UserError,
        Address=Address,
        u256=u256,
        u64=u64,
        u32=u32,
        TreeMap=TreeMap,
    )
    gl_mod.gl = gl_object

    sys.modules["genlayer"] = gl_mod
    return gl_mod


_ensure_genlayer_module()


# ─────────────────────────────────────────────────────────────
# 4. Pytest Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def vm():
    _CURRENT_VM.clear()
    _CURRENT_VM.sender = Address("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    _CURRENT_VM.value = u256(0)
    return _CURRENT_VM


@pytest.fixture
def agent_account():
    return Address("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


@pytest.fixture
def target_contract():
    return Address("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")


@pytest.fixture
def user_caller():
    return Address("0xcccccccccccccccccccccccccccccccccccccccc")
