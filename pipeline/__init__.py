"""Pipeline orchestration for FinDroid-BD 400 (phases 0-8, scriptable)."""

from .run_pipeline import PHASE_ORDER, PHASES, Pipeline, main

__all__ = ["PHASES", "PHASE_ORDER", "Pipeline", "main"]
