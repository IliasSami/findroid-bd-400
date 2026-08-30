"""Deterministic simulated seed catalogue for benign candidates.

Anchored on the real, verified BD seed packages in
``metadata/fintech_seed_packages.csv``. Every candidate generated here carries
``origin`` in its evidence string so no simulated entry can be mistaken for a
real acquisition.

Two provenance classes exist:

* **Real anchors** (from the CSV) — genuine package identifiers with real
  evidence strings. They still pass through the mock Play verifier.
* **Synthetic fills** (this module) — clearly-simulated development benchmark
  entries with ``package_id`` under the ``mock.bd.*`` namespace. They exist only
  to exercise the funnel at target volume and are labelled SIMULATED in every
  downstream artifact.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SeedPackage:
    package_id: str
    app_name: str
    organisation: str
    country: str
    tier: int
    subsector: str
    verification_status: str
    evidence: str
    derived: bool = False  # True => synthetic development fill

    @property
    def is_collision(self) -> bool:
        return self.verification_status == "collision"

    @property
    def is_confirmed(self) -> bool:
        return self.verification_status == "confirmed"

    @property
    def is_unverified(self) -> bool:
        return self.verification_status == "unverified"

    @property
    def is_synthetic(self) -> bool:
        return self.derived or self.package_id.startswith("mock.")


def load_seed_packages(path: Path) -> list[SeedPackage]:
    """Load the seed package catalogue from CSV (row-original provenance)."""
    out: list[SeedPackage] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            out.append(
                SeedPackage(
                    package_id=row["package_id"].strip(),
                    app_name=row["app_name"].strip(),
                    organisation=row["organisation"].strip(),
                    country=row["country"].strip(),
                    tier=int(row["tier"].strip()),
                    subsector=row["subsector"].strip(),
                    verification_status=row["verification_status"].strip(),
                    evidence=row["evidence"].strip(),
                )
            )
    return out


# Synthetic development fills. Explicitly NOT real listings. They provide
# benign volume beyond the real anchors and exercise subsector diversity
# (lending, insurance, investment, microfinance, fintech utility) that the
# real catalogue does not cover. Every row is flagged SIMULATED.
_SYNTHETIC_FILLS: list[SeedPackage] = [
    SeedPackage(
        package_id="mock.bd.wallet001",
        app_name="TestWallet 001",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="mfs_wallet",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.wallet002",
        app_name="TestWallet 002",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="mfs_wallet",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.wallet003",
        app_name="TestWallet 003",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="mfs_wallet",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.wallet004",
        app_name="TestWallet 004",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="mfs_wallet",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.wallet005",
        app_name="TestWallet 005",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="mfs_wallet",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.agent00a",
        app_name="TestAgent 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="mfs_agent",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.agent00b",
        app_name="TestAgent 00B",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="mfs_agent",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.bank00a",
        app_name="TestBank 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="bank_retail",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.bank00b",
        app_name="TestBank 00B",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="bank_retail",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.bank00c",
        app_name="TestBank 00C",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="digital_banking",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.merchant00a",
        app_name="TestMerchant 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="merchant_pos",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.lend00a",
        app_name="TestLoan 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="lending",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.lend00b",
        app_name="TestLoan 00B",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="lending",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.ins00a",
        app_name="TestInsure 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="insurance",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.inv00a",
        app_name="TestInvest 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="investment",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.micro00a",
        app_name="TestMicro 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="microfinance",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.ftu00a",
        app_name="TestFTN 00A",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="fintech_utility",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.ftu00b",
        app_name="TestFTN 00B",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="fintech_utility",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.ftu00c",
        app_name="TestFTN 00C",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="fintech_utility",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
    SeedPackage(
        package_id="mock.bd.ftu00d",
        app_name="TestFTN 00D",
        organisation="Mock Org",
        country="BD",
        tier=1,
        subsector="fintech_utility",
        verification_status="synthetic",
        evidence="SIMULATED development benchmark entry — not a real Play listing",
        derived=True,
    ),
]

_SUBSECTOR_LABEL: dict[str, str] = {
    "mfs_wallet": "mobile financial service wallet",
    "mfs_agent": "mobile financial service agent",
    "bank_retail": "retail banking",
    "digital_banking": "digital banking",
    "psp_wallet": "payment service provider wallet",
    "merchant_pos": "merchant point of sale",
    "sme_ledger": "SME ledger / merchant record keeping",
    "interop_rail": "interoperability rail",
    "remittance": "remittance",
    "neobank": "neobank",
    "crypto_exchange": "crypto exchange",
    "crypto_wallet": "crypto wallet",
    "lending": "consumer lending",
    "investment": "investment / brokerage",
    "insurance": "insurance",
    "microfinance": "microfinance",
    "fintech_utility": "fintech adjacent utility",
}


def package_label(p: SeedPackage) -> str:
    return _SUBSECTOR_LABEL.get(p.subsector, p.subsector)


def load_benign_seed_catalog(seed_csv: Path) -> dict[str, SeedPackage]:
    """Merge CSV seeds + synthetic fills keyed by package_id.

    Collision entries and the two UPay impostors are carried in the catalog
    (so the verifier can *see* them and reject them), but discovery never
    releases them.
    """
    merged: dict[str, SeedPackage] = {}
    for p in load_seed_packages(seed_csv):
        merged[p.package_id] = p
    for p in _SYNTHETIC_FILLS:
        merged[p.package_id] = p
    return merged
