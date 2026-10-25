"""Candidate patterns for security operations; shared by registered rule packs."""
import re

# Candidate coverage is intentionally broader than semantic operation models.
# No nearby protection token or unrelated file can suppress these candidates.
PATTERNS = {
    'origin_response_review': r'''(?i)\b(?:setHeader|addHeader|set_header|Append|Add|Set|header|withHeader|insert_header|append_header|setValue|addValue)\s*\([^\r\n;]{0,128}["']Access-Control-Allow-Origin(?::[^"'\r\n]*)?["']|\b(?:headers|Headers)\s*\[\s*["']Access-Control-Allow-Origin["']\s*\]\s*=''',
    'literal_key_fallback_review': r'''(?i)\b(?:[A-Za-z_]*key|[A-Za-z_]*secret|[A-Za-z_]*token)\b[^\r\n;]{0,160}(?:getenv|GetEnvironmentVariable|process\s*\.\s*env|Platform\s*\.\s*environment|ENV\s*\[|env::var)[^\r\n;]{0,256}(?:\?\?|\|\||\?:|\bor\b|unwrap_or\s*\(|,\s*)\s*["'][^"'\r\n]+["']''',
    'bulk_binding_review': r'\b(?:Object\s*\.\s*assign|BeanUtils\s*\.\s*copyProperties|TryUpdateModel(?:Async)?|UpdateModel|PopulateObject|bulk_(?:update|insert)_mappings|assign_attributes|update_attributes)\s*\(|(?:->|::)\s*(?:forceFill|fill|setAttributes)\s*\(|\b(?:JsonConvert\s*\.\s*)?DeserializeObject\s*<',
    'anonymous_operation_review': r'\[AllowAnonymous(?:Attribute)?\b|@PermitAll\b|\bpermitAll\s*\(|\b(?:AllowAnonymous|withAnonymousAccess)\s*\(',
    'tenant_data_scope_review': r'(?i)\b(?:where|filter|find|query|select|update|delete|find_by|findOne|Find|Where)\b[^\r\n;]{0,256}\b(?:tenant_?id|organization_?id|organisation_?id)\b',
}


def candidate_view(kind, comments, code):
    """Keep literal arguments while requiring the operation to be code."""
    if kind in {'bulk_binding_review','anonymous_operation_review'}:
        return code
    if kind not in PATTERNS:
        return comments
    output=['\n' if char=='\n' else '\r' if char=='\r' else ' ' for char in comments]
    for match in re.finditer(PATTERNS[kind],comments):
        if code[match.start():match.start()+1].strip():
            output[match.start():match.end()] = comments[match.start():match.end()]
    return ''.join(output)

GUIDANCE = {
    'origin_response_review': ('Response Origin Policy Review',
        'A response-origin policy is declared or constructed. Trace the value into the response, including credential handling and environment overrides.',
        'An attacker-selected origin can expose sensitive browser-readable responses if the effective policy and resource access permit it.',
        'Use exact approved origins and verify credentialed preflight and actual responses. Authentication and authorization remain independent controls.'),
    'literal_key_fallback_review': ("Security Configuration Fallback Review",
        'Security-named configuration has a literal fallback candidate. Determine whether that value reaches a cryptographic key or an authentication secret.',
        'A predictable fallback used as an active key can enable forgery or disclosure. A fixture, unused value or non-secret identifier does not establish that impact.',
        'Fail closed when required security configuration is missing; load production keys from an appropriate secret store and verify the failure path.'),
    'bulk_binding_review': ('Bulk Object Field Binding Review',
        'An operation copies or binds object fields in bulk. Review the exact source, destination type and writable fields; this candidate does not establish mass assignment.',
        'If untrusted fields can set privilege, ownership or protected state, a caller may exceed the intended operation permissions.',
        'Use an explicit request schema and an operation-specific writable-field allowlist. Assign ownership, tenant and privilege fields from trusted server context.'),
    'anonymous_operation_review': ('Explicit Anonymous Operation Review',
        'An explicit anonymous-access declaration is present. Associate it with the affected route and operations, including inherited policy requirements.',
        'Public access is often intentional. A defect exists only if the reachable operation requires identity or resource permissions that are not enforced.',
        'Declare public entry points intentionally and enforce the required resource permissions at sensitive operations. Test neighboring protected routes and override behavior.'),
    'tenant_data_scope_review': ('Tenant Data Constraint Review',
        'A tenant or organization identifier is associated with a data operation. Verify its provenance and application-specific isolation invariant.',
        'Caller-selected tenant identity or an incomplete constraint may expose another tenant\'s records. Marker presence and absence do not establish isolation.',
        'Derive the effective tenant from trusted authenticated context, apply it to the exact data operation and verify access using two distinct tenants.'),
}


def rule_document(platform, kind):
    title, description, impact, remediation = GUIDANCE[kind]
    return dict(format='daksh-pattern-rule/v1', id=platform+'.'+kind, title=title,
                order=950, category='Security Operation Context',
                detection=dict(pattern=PATTERNS[kind], conditions=['WHEN PRESENT ${pattern}']),
                reporting=dict(type='area_of_interest', reason=description,
                               description=description, impact=impact, remediation=remediation,
                               reviewer='Verify the exact source, operation and applicable controls. This is a review candidate, not a confirmed vulnerability.',
                               review_steps=[description, 'Check the control on the actual path; unrelated markers must not suppress the candidate.',
                                             'Validate a reachable unsafe case and a protected control before confirming the issue.'],
                               recommendations=[remediation]),
                scan_config=dict(match_mode='line', context_lines_before='2', context_lines_after='2',
                                 aggregate='file', highlight_enabled='true', highlight_color='yellow'))
