"""Per-scan engine selection, independent of deployment environment."""

MODES = ("v1", "v2", "both")
RULE_MODES = {'pattern': 'v1', 'semantic': 'v2', 'both': 'both'}


def configure_engines(repository_root, mode, custom_packs=(), rule_mode=None):
    if rule_mode is not None:
        if rule_mode not in RULE_MODES:
            raise ValueError('Rule mode must be pattern, semantic, or both')
        if mode != RULE_MODES[rule_mode]:
            raise ValueError('Rule mode and legacy engine selection conflict')
    if mode not in MODES:
        raise ValueError("RDL engine must be v1, v2, or both")
    if custom_packs and mode == 'v1':
        raise ValueError('Custom Semantic Rule packs require semantic or both mode')
    from .custom import CustomRuleRunner
    custom_runner = CustomRuleRunner(custom_packs) if custom_packs else None
    from state import runtime_state as state
    from .shadow import default_shadow_runner

    state.rdl_engine_mode = mode
    runner = default_shadow_runner(repository_root)
    runner.enabled_override = mode != "v1"
    runner.v1_enabled = mode != "v2"
    runner.semantic_only = rule_mode == 'semantic'
    runner.custom_runner = custom_runner
    runner._reviewed.clear()
    if hasattr(runner, "_baseline"):
        runner._baseline.seen.clear()
    return runner


def v1_enabled():
    from state import runtime_state as state
    return getattr(state, "rdl_engine_mode", "v1") != "v2"
