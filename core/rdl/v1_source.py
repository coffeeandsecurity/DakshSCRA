"""Offset-preserving source filters for legacy hotspot evidence."""
import re
import hashlib
from pathlib import Path
from functools import lru_cache
from .source_review import source_views
from .literal_review import php_process_call_names, php_regex_replacements, promise_resolver_timers, resource_algorithm_words


@lru_cache(maxsize=32)
def _views(path, content):
    from utils.source_cache import current_snapshot
    snapshot = current_snapshot()
    if snapshot is None:
        return source_views(path, content)
    return snapshot.memo(('v1-source-views', path, hashlib.sha256(content.encode('utf-8', errors='surrogatepass')).hexdigest()),
                         lambda: source_views(path, content))


def review_text(reference, path, content, project_root=None):
    """Keep unknown/custom and intentional review-surface rules unchanged."""
    ref = str(reference).replace('\\', '/')
    if not ref.startswith('logic/rdl/v1/'):
        return content
    stem = Path(ref).stem
    scope = ref[len('logic/rdl/v1/'):].rsplit('/', 1)[0]
    from .mobile_precision import refine
    content = refine(stem, path, content, project_root)
    if scope == 'common/core' and stem == 'ipv4_ipv6_address':
        from .ip_literals import address_view
        selected, code = _views(str(path), content)
        return address_view(path, content, selected, code)
    if scope == 'common/core' and stem == 'todo_comments':
        from .source_review import comments_only
        without_comments, _ = _views(str(path), content)
        return comments_only(content, without_comments)
    # Broad review surfaces intentionally include documentation and examples.
    if scope.startswith('filepaths') or (scope == 'common/core' and stem not in {'insecure_http_communication', 'insecure_cryptographic_algorithm'}):
        return content
    if stem in {'fast_hashing_of_passwords', 'password_self_comparison', 'reversible_password_storage'}:
        from .literal_review import password_security_operations
        selected, code = _views(str(path), content)
        return password_security_operations(selected, code, stem)
    if scope.startswith('javascript/framework/') and stem.endswith('_hardcoded_secret_material'):
        from .literal_review import javascript_secret_values
        return javascript_secret_values(content)
    if stem == 'jwt_claims_read_without_local_validation':
        from .literal_review import jwt_claim_operations
        selected, code = _views(str(path), content)
        return jwt_claim_operations(selected, code)
    if scope.startswith('dotnet/framework/') and stem.endswith('_hardcoded_secret_material'):
        from .accuracy_review import review_operations
        return review_operations('dotnet.' + stem, path, content)
    # Embedded secrets remain relevant even when commented out.
    if any(word in stem for word in ('secret', 'password', 'credential', 'private_key', 'access_key', 'hardcoded')):
        if scope.startswith('java/framework/') and stem.endswith('_hardcoded_secret_material'):
            from .literal_review import secret_placeholders
            return secret_placeholders(content)
        return content
    selected, code = _views(str(path), content)
    from .accuracy_review import review_operations
    selected = review_operations(stem, path, selected)
    from .security_patterns import PATTERNS, candidate_view
    if stem in PATTERNS:
        selected = candidate_view(stem, selected, code)
    if scope == 'python/core' and stem in {'predictable_randomness_review', 'flask_request_data_review'}:
        selected = code
    if scope == 'javascript/core' and stem == 'server_side_request_forgery_ssrf':
        from .literal_review import javascript_request_operations
        selected = javascript_request_operations(selected, code)
    if scope == 'java/core' and stem == 'sensitive_values_in_log_output':
        from .literal_review import java_sensitive_logs
        selected = java_sensitive_logs(selected, code)
    if scope == 'java/core' and stem in {'disabled_csrf_protection', 'insecure_package_java_util_random'}:
        from .literal_review import java_security_operations
        selected = java_security_operations(selected, code, stem)
    if scope == 'java/core' and stem == 'jsp_unescaped_expression_output':
        from .literal_review import jsp_output_expressions
        selected = jsp_output_expressions(path, content)
    if scope in {'c/core', 'cpp/core'} and stem in {'access_to_freed_memory', 'access_to_freed_memory_2', 'memory_copy_size_and_overlap_review'}:
        selected = code
    if scope in {'c/core', 'cpp/core'} and stem in {'potential_format_string_attack', 'potential_format_string_attack_printf_fprintf_etc', 'format_string_misuse_in_c_streams'}:
        from .native_call_review import dynamic_format_calls
        selected = dynamic_format_calls(selected, code)
    if scope == 'java/core' and stem == 'file_inclusion_vulnerability':
        from .literal_review import java_fixed_destinations
        selected = java_fixed_destinations(selected)
    if scope == 'php/core':
        if stem == 'untrusted_inputs_request_get_post_cookie':
            # PHP superglobals are case-sensitive complete identifiers.
            selected = re.sub(r'\$_(?:REQUEST|GET|POST|COOKIE)\w*',
                              lambda m: m.group() if re.fullmatch(r'\$_(?:REQUEST|GET|POST|COOKIE)', m.group()) else _blank(m),
                              selected, flags=re.I)
        if stem == 'command_injection_shell_exec_exec_passthru_system_popen_backtick':
            selected = php_process_call_names(selected)
            selected = _data_call_names(selected, code, r'\b(?:shell_exec|exec|passthru|system|popen)\s*\(')
        elif stem == 'regular_expression_injection_preg_replace_with_e_modifier_or_untrusted_input':
            selected = _data_call_names(selected, code, r'\bpreg_replace\s*\(')
            selected = php_regex_replacements(selected)
        elif stem == 'object_injection_via_serialization':
            selected = _deserialization_calls(str(path), selected)
    if stem == 'insecure_cryptographic_algorithm' and scope == 'common/core':
        selected = resource_algorithm_words(path, selected)
    if stem == 'insecure_method_call_eval_settimeout_setinterval':
        selected = promise_resolver_timers(selected)
    if stem in {'ios_insecure_url_usage', 'react_native_insecure_http_usage', 'insecure_http_communication'} or stem.endswith('_insecure_transport_setting'):
        from .literal_review import document_http_identifiers
        selected = document_http_identifiers(selected)
    return selected


def _blank(match):
    return ''.join(c if c in '\r\n' else ' ' for c in match.group())


def _data_call_names(text, code, pattern):
    # Remove illustrative calls inside literal data without changing arguments
    # or offsets of executable calls. Unresolved syntax remains a review lead.
    masked = list(text)
    for match in re.finditer(pattern, text, re.I):
        if not re.search(pattern, code[match.start():match.end()], re.I):
            masked[match.start():match.end()] = _blank(match)
    return ''.join(masked)


def _deserialization_calls(path, text):
    if '${' in text or '{$' in text:
        return text  # Unresolved executable interpolation remains reviewable.
    from .executor import ExecutionResult, ExecutionOutcome
    from .php_call_review import review_deserialization
    result = review_deserialization(ExecutionResult(ExecutionOutcome.NO_MATCH, '', ()), path, text)
    if result.errors or len(result.witnesses) >= 100:
        return text
    retained = {(e.location.line, e.location.column) for e in result.evidence if e.location}
    masked = list(text)
    for match in re.finditer(r'\bunserialize\s*\(', text, re.I):
        line = text.count('\n', 0, match.start()) + 1
        column = match.start() - text.rfind('\n', 0, match.start())
        if (line, column) not in retained:
            masked[match.start():match.start()+len('unserialize')] = ' ' * len('unserialize')
    return ''.join(masked)
