from src.m3_correlation.domain.investigation import InvestigationContext
from .rules import apply_rules

class CorrelationEngine:
    def correlate(self, ctx: InvestigationContext) -> InvestigationContext:
        """
        Applies deterministic rules to infer relationships and order timeline events.
        Mutates the InvestigationContext in place.
        """
        apply_rules(ctx)
        return ctx
