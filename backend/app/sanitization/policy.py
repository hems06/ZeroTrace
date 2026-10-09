"""Sanitization policy references.

Standards (NIST SP 800-88 Rev.1, IEEE 2883-2022, ATA/NVMe secure-erase
capabilities) are treated as policy guidance for choosing a method -- not as
interchangeable algorithms. Clear / Purge / Destroy are distinct outcomes;
this module documents which emulated method maps to which outcome and what
its real-world limitations are, so the certificate can state them honestly.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SanitizationMethod:
    key: str
    label: str
    policy_level: str  # clear | purge | destroy
    policy_reference: str
    passes: list[str]  # "zero" | "one" | "random"
    limitations: str


METHODS: dict[str, SanitizationMethod] = {
    "clear-single-pass-zero": SanitizationMethod(
        key="clear-single-pass-zero",
        label="Clear - Single-pass zero overwrite",
        policy_level="clear",
        policy_reference="NIST SP 800-88 Rev.1 (Clear) / IEEE 2883-2022 (Clear)",
        passes=["zero"],
        limitations=(
            "Logical overwrite only. Appropriate for Clear-level sanitization of "
            "conventional magnetic media and file-level re-use scenarios. Does not "
            "guarantee removal of data from flash translation layer over-provisioned "
            "or wear-leveled areas on SSDs/flash media."
        ),
    ),
    "purge-three-pass-overwrite": SanitizationMethod(
        key="purge-three-pass-overwrite",
        label="Purge (emulated) - 3-pass overwrite (zero / one / random)",
        policy_level="purge",
        policy_reference="NIST SP 800-88 Rev.1 (Purge, overwrite-emulated) / IEEE 2883-2022 (Purge)",
        passes=["zero", "one", "random"],
        limitations=(
            "This is a software overwrite emulation of a Purge-level outcome. It is "
            "NOT equivalent to a device's built-in ATA Secure Erase, NVMe Sanitize, or "
            "cryptographic erase, and provides no guarantee against recovery from "
            "flash-level remapped or over-provisioned storage. Use native "
            "device-sanitize commands when available for a genuine Purge claim."
        ),
    ),
    "destroy-document-only": SanitizationMethod(
        key="destroy-document-only",
        label="Destroy - Physical destruction (documentation only)",
        policy_level="destroy",
        policy_reference="NIST SP 800-88 Rev.1 (Destroy)",
        passes=[],
        limitations=(
            "ZeroTrace does not perform physical destruction. This method records "
            "an operator attestation that physical destruction was carried out "
            "through an external process; it is not independently verified by this "
            "application."
        ),
    ),
}


def get_method(key: str) -> SanitizationMethod:
    if key not in METHODS:
        raise ValueError(f"Unknown sanitization method '{key}'")
    return METHODS[key]


def list_methods() -> list[dict]:
    return [
        {
            "key": m.key,
            "label": m.label,
            "policy_level": m.policy_level,
            "policy_reference": m.policy_reference,
            "limitations": m.limitations,
            # Full read-back can confirm a zero-fill only.
            "supports_full_readback": bool(m.passes) and m.passes[-1] == "zero",
        }
        for m in METHODS.values()
    ]
