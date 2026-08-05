"""Unit tests for adaf_redteam.lab_env helpers."""

from __future__ import annotations

import os

from adaf_redteam.lab_env import lab_bind_password, lab_bind_user, lab_dc, lab_opt_in


def test_lab_opt_in_requires_exact_value(monkeypatch):
    monkeypatch.delenv("ADAF_RT_LAB", raising=False)
    assert lab_opt_in() is False
    monkeypatch.setenv("ADAF_RT_LAB", "0")
    assert lab_opt_in() is False
    monkeypatch.setenv("ADAF_RT_LAB", "true")
    assert lab_opt_in() is False
    monkeypatch.setenv("ADAF_RT_LAB", "1")
    assert lab_opt_in() is True


def test_lab_dc_only_when_opted_in(monkeypatch):
    monkeypatch.setenv("ADAF_RT_LAB_DC", "dc01.lab.test")
    monkeypatch.delenv("ADAF_RT_LAB", raising=False)
    assert lab_dc() is None
    monkeypatch.setenv("ADAF_RT_LAB", "1")
    assert lab_dc() == "dc01.lab.test"
    monkeypatch.setenv("ADAF_RT_LAB_DC", "  ")
    assert lab_dc() is None


def test_lab_bind_identity_only_when_opted_in(monkeypatch):
    monkeypatch.setenv("ADAF_RT_LAB_BIND_USER", "lab\\certuser")
    monkeypatch.setenv("ADAF_RT_LAB_BIND_PASSWORD", "not-a-real-secret")
    monkeypatch.delenv("ADAF_RT_LAB", raising=False)
    assert lab_bind_user() is None
    assert lab_bind_password() is None
    monkeypatch.setenv("ADAF_RT_LAB", "1")
    assert lab_bind_user() == "lab\\certuser"
    assert lab_bind_password() == "not-a-real-secret"
