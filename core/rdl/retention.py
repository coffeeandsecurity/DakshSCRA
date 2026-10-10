"""Keep review results and analysis limits without a cross-engine ledger."""


def review_record(record):
    """Return a comparison-free record, or None for a clean negative decision."""
    outcome = record.get('v2_outcome')
    unresolved = outcome in {'INDETERMINATE', 'RULE_ERROR', 'SHADOW_ERROR'} or record.get('status') in {'INDETERMINATE', 'RULE_ERROR', 'SHADOW_ERROR'}
    from .assessment import classify_record
    assessed = classify_record(record) != 'not_applicable'
    if not (assessed or outcome == 'MATCH' or record.get('v2_findings') or unresolved
            or record.get('v2_errors') or record.get('v2_limitations')
            or record.get('v2_unavailable_capabilities')):
        return None
    result = {key: value for key, value in record.items()
              if not key.startswith('v1_') and key not in {'authoritative_engine', 'affects_finding'}}
    result['comparison_retained'] = False
    result['status'] = 'INDETERMINATE' if unresolved and outcome not in {'RULE_ERROR', 'SHADOW_ERROR'} else (outcome or record.get('status', 'UNKNOWN'))
    return result
