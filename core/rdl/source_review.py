"""Source-aware refinements for native v2 review; legacy predicates stay auditable."""
import re
from functools import lru_cache
from bisect import bisect_right
import xml.etree.ElementTree as ET
from dataclasses import replace

from pygments.lexers import get_lexer_for_filename, get_lexer_by_name
from pygments.token import Comment, String
from pygments.util import ClassNotFound

from .executor import Evidence, ExecutionOutcome
from .text import execute_text, match_location as location


def source_views(path, content):
    """Mask syntax trivia without moving offsets or altering recorded source."""
    comments, code = list(content), list(content)
    if str(path).lower().endswith(('.jsp', '.jspx')):
        # Server-side template comments can contain complete Java expressions.
        for match in re.finditer(r'<%--[\s\S]*?(?:--%>|$)', content):
            for index in range(match.start(), match.end()):
                if content[index] not in '\r\n':
                    comments[index] = code[index] = ' '
    lex_content = ''.join(comments)
    try:
        lexer = get_lexer_for_filename(str(path), stripnl=False, ensurenl=False)
    except ClassNotFound:
        suffix = str(path).lower().rsplit('.', 1)[-1]
        if suffix not in {'jsx', 'tsx', 'mjs', 'cjs'}:
            return content, content
        lexer = get_lexer_by_name('typescript' if suffix == 'tsx' else 'javascript',
                                 stripnl=False, ensurenl=False)
    # Some lexers require a terminating newline to recognize an EOF line
    # comment. The sentinel is never copied into source/evidence offsets.
    for offset, kind, value in lexer.get_tokens_unprocessed(lex_content+'\n'):
        comment = kind in Comment and kind not in Comment.Preproc and kind not in Comment.PreprocFile
        # PHP documentation blocks are classified as String.Doc by the lexer.
        if str(path).lower().endswith('.php') and kind in String.Doc and value.startswith('/**'):
            comment = True
        literal = kind in String
        if comment or literal:
            for index in range(offset, min(offset + len(value), len(content))):
                if content[index] not in '\r\n':
                    code[index] = ' '
                    if comment:
                        comments[index] = ' '
    return ''.join(comments), ''.join(code)


@lru_cache(maxsize=2)
def compact_trivia(original, masked):
    """Avoid pathological whitespace backtracking while retaining a source map."""
    pieces, changes, delta, cursor = [], [], 0, 0
    for match in re.finditer(r'[ \t]{16,}', masked):
        if original[match.start():match.end()] == match.group():
            continue
        pieces.extend((masked[cursor:match.start()], ' '))
        boundary = match.start() - delta + 1
        delta += len(match.group()) - 1
        changes.append((boundary, delta))
        cursor = match.end()
    pieces.append(masked[cursor:])
    compact = ''.join(pieces)
    boundaries = [item[0] for item in changes]
    line_offsets = [0] + [m.end() for m in re.finditer('\n', compact)]

    def remap(evidence):
        loc = evidence.location
        if not loc or not changes:
            return evidence
        def offset(line, column):
            point = line_offsets[line - 1] + column - 1
            index = bisect_right(boundaries, point) - 1
            return point + (changes[index][1] if index >= 0 else 0)
        return replace(evidence, location=location(loc.path, original,
                       offset(loc.line, loc.column), offset(loc.end_line, loc.end_column)))
    return compact, remap


def provider_review(result, path, text):
    """Check each provider independently, including application permissions."""
    android = '{http://schemas.android.com/apk/res/android}'
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return replace(result, outcome=ExecutionOutcome.INDETERMINATE, witnesses=(),
                       errors=('Cannot resolve provider declarations: ' + str(exc),))
    application = root.find('application')
    inherited = application.attrib if application is not None else {}
    tags = list(re.finditer(r'''<provider\b(?:[^>"']|"[^"]*"|'[^']*')*>''', text))
    providers = list(root.iter('provider'))
    if len(tags) != len(providers):
        return replace(result, outcome=ExecutionOutcome.INDETERMINATE, witnesses=(),
                       errors=('Cannot associate provider attributes with source locations.',))
    witnesses = []
    for node, tag in zip(providers, tags):
        if application is None or node not in list(application):
            continue
        attrs = node.attrib
        if attrs.get(android + 'exported') == 'false' or attrs.get(android + 'enabled') == 'false' or inherited.get(android + 'enabled') == 'false':
            continue
        permission = attrs.get(android + 'permission', inherited.get(android + 'permission', ''))
        read = attrs.get(android + 'readPermission', permission)
        write = attrs.get(android + 'writePermission', permission)
        if read and write:
            continue
        missing = ', '.join(name for name, value in [('read', read), ('write', write)] if not value)
        exported = attrs.get(android + 'exported', 'unspecified; SDK/manifest merge must be resolved')
        detail = 'Provider {}: exported={}; no effective {} permission declared. URI grants and runtime access checks are not evaluated.'.format(attrs.get(android + 'name', '(unnamed)'), exported, missing)
        witnesses.append((Evidence('TEXT_MATCHES', True, location=location(path, text, tag.start(), tag.end()), explanation=detail),))
    return replace(result, outcome=ExecutionOutcome.MATCH if witnesses else ExecutionOutcome.NO_MATCH,
                   evidence=tuple(e for group in witnesses for e in group), witnesses=tuple(witnesses))


def dependency_review(result, path, text):
    # Include dotted/hyphenated artifacts, prereleases and unresolved Gradle variables.
    pattern = r"(?m)^[ \t]*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation)\s*(?:\(\s*)?[\"']([\w.-]+:[\w.-]+:[^\"'\r\n]+)[\"']"
    witnesses = []
    for match in re.finditer(pattern, text):
        detail = 'Declared dependency: ' + match.group(1) + '. Resolved version and advisory status were not checked.'
        if '$' in match.group(1):
            detail += ' The version contains an unresolved Gradle variable.'
        witnesses.append((Evidence('TEXT_MATCHES', True, location=location(path, text, match.start(), match.end()), explanation=detail),))
        if len(witnesses) >= 100:
            break
    return replace(result, outcome=ExecutionOutcome.MATCH if witnesses else ExecutionOutcome.NO_MATCH,
                   evidence=tuple(e for group in witnesses for e in group), witnesses=tuple(witnesses))


GUIDANCE = {
    'file_inclusion_vulnerability': (
        'Request Dispatch Destination Review',
        'A dispatch or redirect destination is computed in the checked code. Its provenance and permitted destinations need review. This check does not establish local file inclusion.',
        'Trace the destination to its caller and enforce permitted routes or local destinations. Review file access separately from redirects.'),
    'react_native_hardcoded_secret_marker': (
        "Client Credential Usage Review",
        'A credential-like literal is embedded in client source. Public API identifiers can be intentional; this check does not establish that the value is active, secret or unrestricted.',
        'Determine the credential type, effective service restrictions and shipped use. Remove and rotate actual exposed secrets; restrict public client API identifiers to the intended application and APIs.'),
    'weak_random_number_generation': (
        "Random Number Generation Review",
        'A non-cryptographic random-number API is present. Display data, simulations and UI fixtures do not establish insecure security-sensitive randomness.',
        'Trace the generated value. Use a cryptographically secure generator for tokens, secrets and other security-sensitive values; assess ordinary display randomness separately.'),
    'file_sharing_without_content_provider': (
        'Outgoing URI Intent Review',
        'An outgoing Intent is constructed with Uri.parse. Its URI may be a remote web URL, a content URI or a local file URI; this predicate does not establish local file exposure or a missing content provider.',
        'Resolve the effective URI scheme and recipient. Use a permission-scoped content URI when sharing private local files; assess remote links and attacker-selected intent targets separately.'),
    'regular_expression_injection_preg_replace_with_e_modifier_or_untrusted_input': (
        'Regular Expression Pattern Review',
        'A replacement pattern remains unresolved or contains the legacy /e modifier. This check does not establish attacker-controlled evaluated content or a PHP runtime that supports that modifier.',
        'Resolve pattern construction, delimiters, modifiers, caller input and the deployed PHP version. Use literal replacements or preg_replace_callback instead of evaluated replacement syntax, and constrain dynamic patterns.'),
    'rdl_conditional_sql_query_with_untrusted_input_and_missing_parameterization': (
        "SQL Input Handling Review",
        'SQL execution and an input marker occur in the checked file. This file-level predicate does not establish that the input changes the query or that a particular statement lacks parameterization.',
        'Inspect the exact source-to-query flow and query arguments. Use bound parameters for values and approved identifiers for dynamic query structure; confirm a defect only where the recorded flow supports it.'),
    'ssrf_file_get_contents_with_user_controlled_url': (
        "File or URL Read Review",
        'A file-reading API receives a variable or input marker. This text check does not resolve whether the argument is a local path, a PHP-assigned upload path, or an attacker-selected network URL.',
        'Resolve the argument and URL scheme at the read operation. Apply path containment to filesystem access and destination restrictions to network access; do not classify local file reads as SSRF.'),
    'ssrf_curl_exec_with_user_controlled_url': (
        "Outbound Request Destination Review",
        'The code initializes or assigns a cURL destination. This text check does not prove that a caller can select the destination or that the request crosses a prohibited network boundary.',
        'Trace the effective URL into the request, including redirects and configuration. Restrict attacker-selectable destinations according to the endpoint policy.'),
    'server_side_request_forgery_ssrf': (
        "Outbound Request Destination Review",
        'A request API is present. This file-level check does not establish attacker control of the destination or whether the code executes in a browser or on a server.',
        'Resolve the execution environment and exact URL flow. Assess SSRF for server-side requests with attacker-selectable destinations; review browser requests against their applicable trust boundaries.'),
    'path_traversal_open_with_user_controlled_path': (
        'File Path Input Review',
        'File opening and a potential input marker occur in the checked source. Their data flow, caller trust and intended filesystem boundary are not established; command-line paths can be intentional.',
        'Trace the path into the file operation and identify the caller and required filesystem boundary. Confirm attacker control and boundary escape before classifying path traversal.'),
    'insecure_cryptographic_algorithm': (
        'Cryptographic Algorithm Use Review',
        'An algorithm marker is present. Purpose, inputs and protocol matter: OTP, breach-range lookups and legacy storage-key identifiers do not establish weak password storage or encryption.',
        'Trace the actual cryptographic operation and its security purpose before confirming an inappropriate algorithm.'),
    'insecure_method_call_viewmodelscope_launch_no_error_handling': (
        'Coroutine Failure Handling Review',
        'A coroutine launch is present without a recognized handler in the checked source. Helpers, scope/context handlers and Result/Flow wrappers may handle failures; no security impact is established.',
        'Trace actual exception propagation and application impact before confirming a failure-handling defect.'),
    'outdated_dependencies': (
        'Dependency Version Review',
        'A dependency version is declared. This check does not compare a resolved dependency graph against releases or security advisories and cannot establish that it is outdated or vulnerable.',
        'Review the resolved dependency versions and relevant advisories before deciding whether to upgrade.'),
    'unsafe_loop_handling_over_arrays_or_strings': (
        'Loop Bounds Review',
        'A loop uses an explicit bound. The rule does not prove that this bound exceeds the accessed allocation or comes from untrusted input.',
        'Compare every indexed buffer capacity with the loop bound, including values validated by callers. Confirm an out-of-range access before treating this as a defect.'),
    'unsafe_loop_handling_over_arrays_or_vectors': (
        'Loop Bounds Review',
        'A loop uses an explicit bound. Absence of a named bounds-check helper does not prove an out-of-bounds access.',
        'Compare every indexed buffer capacity with the loop bound, including values validated by callers. Confirm an out-of-range access before treating this as a defect.'),
    'unsafe_type_conversion_reinterpret_cast': (
        'Pointer Cast Review',
        'A reinterpret_cast is present. This operation alone does not demonstrate invalid aliasing, alignment, lifetime, or a security vulnerability.',
        'Review the actual source and destination types, alignment, object lifetime and caller contract. JNI byte-buffer conversions and correctly typed callbacks can be legitimate.'),
    'stack_trace_or_error_disclosure': (
        'Stack Trace Logging Review',
        'The code prints an exception stack trace. Whether sensitive details reach an untrusted user depends on the log destination and access controls.',
        'Check the logging destination, production configuration, and access to logs before classifying this as information disclosure.'),
    'insecure_pendingintent_missing_immutability_flag': (
        'PendingIntent Mutability Review',
        'A PendingIntent factory is present without a recognized immutable flag in this file. Flags can be supplied through helpers, and framework fill-in workflows can require mutability; unsafe use is not established.',
        'Resolve factory flags and explicit target through helpers. Verify recipients, fill-in data and whether mutability is required for this operation.'),
    'minification-disabled': (
        'Code Shrinking Configuration Review',
        'A non-debug or unresolved build scope disables code shrinking. Library configuration alone does not establish missing application release hardening.',
        'Verify shrinking and obfuscation in the selected final application release artifact.'),
    'user-trust-anchors': (
        'Certificate Trust Policy Review',
        'A network configuration enables user-installed trust anchors in the recorded scope. Debug-only and domain overrides must be resolved before asserting release interception.',
        'Review the selected resource, inherited policy and most specific domain configuration alongside endpoint requirements.'),
    'debuggable_build_enabled': (
        "Debug Mode Configuration Review",
        'A non-debug or unresolved build scope enables debugging. Resolve the selected production build before treating this as release exposure.',
        'Disable debugging in shipped builds and verify the merged manifest and artifact.'),
    'exported_components': (
        "Exported Component Access Review",
        'A component is externally accessible without a resolved signature restriction. Export alone does not prove unauthorized access.',
        'Resolve merged manifests, platform defaults, caller authorization and runtime guards for each component.'),
    'allow_backup': (
        "Application Backup Review",
        'Application backup is enabled. Actual inclusion, encryption and transfer behavior depend on referenced backup policies, build variants and Android versions.',
        'Review cloud and device-transfer rules alongside stored secrets and key recovery; do not infer exposure from the allowBackup flag alone.'),
    'cleartext_traffic': (
        'Cleartext Network Policy Review',
        'A manifest or scoped network configuration permits cleartext traffic; the effective resource, domain and transmitted data must be checked.',
        'Review the selected build and domain policy. Remove cleartext permission for sensitive endpoints; certificate revocation and debug exceptions require contextual assessment.'),
    'unsafe_intent_filters': (
        "Deep Link Intent Filter Review",
        'An externally accessible browsable filter registers a URI. Registration alone does not establish unsafe handling.',
        'Validate routing and authentication in the receiving code, including scheme, domain and path checks.'),
    'insecure_permissions': (
        "Permission Handling Review",
        'The manifest requests a sensitive permission. This is a capability declaration, not proof of excessive access or insecure use.',
        'Verify that each permission is required and that runtime requests, platform version behavior and storage access match the intended feature.'),
    'content_providers_with_no_permissions': (
        'Content Provider Access Review',
        'A provider lacks a declared permission for at least one access direction and is not explicitly non-exported or disabled. Resolve SDK defaults, manifest merging, URI grants and runtime checks before confirming unauthorized access.',
        'If external access is unnecessary, disable export. Otherwise apply appropriate permissions and review any URI grants and path-specific or runtime access checks.'),
    'potential_memory_leak_use_of_new_without_delete': (
        'Allocation Ownership Review',
        'A new expression is present without a recognized release or ownership helper in the checked file. Ownership may be transferred or released elsewhere; a leak is not established.',
        'Trace allocation ownership through callers and destructors. Confirm the object remains unreleased before adding cleanup; prefer an appropriate RAII owner.'),
}


def comments_only(content, without_comments):
    """Retain comment characters only, at their original source offsets."""
    return ''.join(original if original != masked else ('\n' if original == '\n' else '\r' if original == '\r' else ' ')
                   for original, masked in zip(content, without_comments))


def review_source(entry, document, baseline, path, content, project_root, views):
    stem = entry['rule_id'].rsplit('.', 1)[-1]
    guidance = GUIDANCE.get(stem)
    if stem == 'stack_trace_or_error_disclosure' and entry['scope'] != 'java/core':
        guidance = None
    if entry['path_rule']:
        return baseline, (), guidance
    if content.startswith('\x03\x00\x08\x00'):
        reason = 'Compiled Android XML must be decoded before textual source checks; string-pool matches do not establish application behavior.'
        return replace(baseline, outcome=ExecutionOutcome.INDETERMINATE,
                       witnesses=(), evidence=(), errors=(reason,)), (reason,), guidance
    without_comments, code = views
    # Commented credentials are still evidence of embedded secret material.
    secrets = any(word in entry['rule_id'].lower() for word in ('credential', 'secret', 'password', 'private_key', 'private-key', 'hardcoded', 'access_key', 'access-key'))
    comment_rule = stem in {'todo_comments'}
    selected = comments_only(content, without_comments) if comment_rule else content if secrets else without_comments
    from .mobile_precision import refine
    selected = refine(stem, path, selected, project_root)
    if entry['scope'] == 'common/core' and stem == 'ipv4_ipv6_address':
        from .ip_literals import address_view
        selected = address_view(path, content, without_comments, code)
    from .accuracy_review import review_operations
    selected = review_operations(entry['rule_id'], path, selected)
    from .security_patterns import PATTERNS, candidate_view
    if stem in PATTERNS:
        selected = candidate_view(stem, without_comments, code)
    if entry['scope'] == 'java/core' and stem == 'sensitive_values_in_log_output':
        from .literal_review import java_sensitive_logs
        selected = java_sensitive_logs(without_comments, code)
    if entry['scope'] == 'java/core' and stem in {'disabled_csrf_protection', 'insecure_package_java_util_random'}:
        from .literal_review import java_security_operations
        selected = java_security_operations(selected, code, stem)
    if entry['scope'] == 'java/core' and stem == 'jsp_unescaped_expression_output':
        from .literal_review import jsp_output_expressions
        selected = jsp_output_expressions(path, content)
    if entry['scope'] in {'c/core', 'cpp/core'} and stem in {'access_to_freed_memory', 'access_to_freed_memory_2', 'memory_copy_size_and_overlap_review'}:
        selected = code
    if entry['scope'] in {'c/core', 'cpp/core'} and stem in {'potential_format_string_attack', 'potential_format_string_attack_printf_fprintf_etc', 'format_string_misuse_in_c_streams'}:
        from .native_call_review import dynamic_format_calls
        selected = dynamic_format_calls(selected, code)
    if entry['scope'].startswith('java/framework/') and stem.endswith('_hardcoded_secret_material'):
        from .literal_review import secret_placeholders
        selected = secret_placeholders(selected)
    if entry['scope'] == 'java/core' and stem == 'file_inclusion_vulnerability':
        from .literal_review import java_fixed_destinations
        selected = java_fixed_destinations(selected)
    if stem == 'potential_memory_leak_use_of_new_without_delete':
        selected = code
    if entry['scope'] == 'python/core' and stem in {'predictable_randomness_review', 'flask_request_data_review'}:
        selected = code
    from .literal_review import (shell_literals, kotlin_dynamic_literals,
                                 promise_resolver_timers, resource_algorithm_words,
                                 php_process_call_names, php_regex_replacements)
    if entry['scope'] == 'php/core' and stem == 'command_injection_shell_exec_exec_passthru_system_popen_backtick':
        selected = php_process_call_names(selected)
    if entry['scope'] == 'php/core' and stem == 'regular_expression_injection_preg_replace_with_e_modifier_or_untrusted_input':
        selected = php_regex_replacements(selected)
    if entry['scope'] == 'bash/core':
        selected = shell_literals(selected, stem)
    if secrets and str(path).endswith(('.kt', '.kts')):
        selected = kotlin_dynamic_literals(selected)
    if stem == 'insecure_method_call_eval_settimeout_setinterval':
        selected = promise_resolver_timers(selected)
    if stem == 'insecure_cryptographic_algorithm' and entry['scope'] == 'common/core':
        selected = resource_algorithm_words(path, selected)
    if stem in {'ios_insecure_url_usage', 'react_native_insecure_http_usage', 'insecure_http_communication'} or stem.endswith('_insecure_transport_setting'):
        # Namespace identifiers and external document types are not request URLs.
        from .literal_review import document_http_identifiers
        selected = document_http_identifiers(selected)
        if str(path).endswith('.pbxproj'):
            selected = re.sub(r'http://(?:localhost|127\.0\.0\.1)(?=[:/])',
                              lambda m: ' ' * len(m.group()), selected)
    if stem == 'react_native_hardcoded_secret_marker':
        # Redux action identifiers contain no credential assignment.
        def action_identifier(match):
            name, value = match.group(1), match.group(3)
            if name.replace('_', '').casefold() == value.replace('_', '').casefold():
                return ' ' * len(match.group())
            return match.group()
        selected = re.sub(r"\bexport\s+const\s+(set_[a-z_]*(?:token|password|secret)[a-z_]*)\s*=\s*([\"'])([A-Za-z_]+)\2",
                          action_identifier, selected)
    if entry['scope'] == 'javascript/core' and stem == 'server_side_request_forgery_ssrf':
        from .literal_review import javascript_request_operations
        selected = javascript_request_operations(selected, code)
    if entry['scope'].startswith('javascript/framework/') and stem.endswith('_hardcoded_secret_material'):
        from .literal_review import javascript_secret_values
        selected = javascript_secret_values(selected)
    if stem in {'fast_hashing_of_passwords', 'password_self_comparison', 'reversible_password_storage'}:
        from .literal_review import password_security_operations
        selected = password_security_operations(selected, code, stem)
    if stem == 'jwt_claims_read_without_local_validation':
        from .literal_review import jwt_claim_operations
        selected = jwt_claim_operations(selected, code)
    compact, remap = compact_trivia(content, selected)
    result = execute_text(document, path, project_root, compact, collect_matches=True)
    result = replace(result, evidence=tuple(remap(e) for e in result.evidence),
                     witnesses=tuple(tuple(remap(e) for e in group) for group in result.witnesses))
    if entry['rule_id'] == 'android.user-trust-anchors' or (stem == 'cleartext_traffic' and str(path).endswith('.xml') and 'network-security-config' in without_comments):
        from .mobile_review import review_network_config
        result = review_network_config(entry, result, path, without_comments)
    if stem == 'exported_components' and str(path).replace('\\', '/').split('/')[-1] == 'AndroidManifest.xml':
        from .mobile_review import _manifest
        result = _manifest(dict(entry, mobile_check='manifest-export'), result, path, without_comments)
    if stem == 'unsafe_intent_filters':
        from .mobile_review import _manifest
        result = _manifest(dict(entry, mobile_check='manifest-deeplink', description='Deep-link intent filter review; registration alone does not prove unsafe handling.'), result, path, without_comments) if str(path).endswith('.xml') else replace(result, outcome=ExecutionOutcome.NO_MATCH, evidence=(), witnesses=(), errors=())
    if stem == 'outdated_dependencies':
        result = dependency_review(result, path, selected)
    if entry['scope'] == 'php/core' and stem == 'object_injection_via_serialization':
        from .php_call_review import review_deserialization
        result = review_deserialization(result, path, without_comments)
    if entry['scope'].startswith('php/framework/') and stem.endswith('_hardcoded_secret_material'):
        from .php_call_review import review_secret_assignments
        result = review_secret_assignments(result, path, without_comments)
    if entry.get('php_check') == 'sensitive-log':
        from .php_call_review import review_sensitive_logging
        result = review_sensitive_logging(result, path, without_comments)
    if entry['rule_id'] == 'android.minification-disabled' or stem == 'debuggable_build_enabled':
        from .mobile_review import review_gradle
        result = review_gradle(entry, result, path, without_comments, code)
    if entry.get('mobile_check'):
        from .mobile_review import review_mobile
        result = review_mobile(entry, result, path, without_comments, code, project_root)
    if stem == 'credential_http_request':
        from .mobile_review import review_mobile
        result = review_mobile(dict(entry, mobile_check='credential-http-request', file_patterns=['*.java']), result, path, without_comments, code, project_root)
    if entry.get('project_check') or stem == 'logout_retained_state':
        from .mobile_review import review_mobile
        selected_check = entry.get('project_check', 'logout')
        result = review_mobile(dict(entry,mobile_check='project-'+selected_check,file_patterns=entry.get('file_patterns',['*.js','*.jsx','*.ts','*.tsx','*.mjs','*.cjs'])),result,path,without_comments,code,project_root)
    if stem in {'privacy_api_purpose','credential_backup_correlation'}:
        from .mobile_review import review_mobile
        check='privacy' if stem=='privacy_api_purpose' else 'backup'
        result=review_mobile(dict(entry,mobile_check='project-'+check,file_patterns=['Info.plist' if check=='privacy' else 'AndroidManifest.xml']),result,path,without_comments,code,project_root)
    if entry.get('client_check') or stem == 'otp_completion_navigation':
        from .client_review import review_client
        selected_entry = dict(entry, client_check=entry.get('client_check', 'otp-navigation'))
        result = review_client(selected_entry, result, path, without_comments, code)
    if entry.get('java_check') == 'datasource-secret':
        from .java_review import datasource_credentials
        result = datasource_credentials(result, path, without_comments)
    notes = []
    source_parts = str(path).replace('\\', '/').split('/')
    source_set = next((source_parts[index+1] for index, part in enumerate(source_parts[:-1]) if part == 'src'), '')
    if source_set:
        notes.append('Source set: '+source_set+'. '+('Test/fixture evidence does not establish behavior in a shipped application.' if source_set in {'test', 'androidTest', 'testFixtures', 'androidTestFixtures'} else 'Build-variant inclusion and merged configuration must be resolved.'))
    if selected != content and (baseline.outcome == ExecutionOutcome.MATCH or result.outcome == ExecutionOutcome.MATCH):
        notes.append('V2 evaluates source with comments or verified literal-only matches masked at their original offsets; recorded excerpts retain the original source.')
    if stem == 'content_providers_with_no_permissions' and result.outcome == ExecutionOutcome.MATCH:
        result = provider_review(result, path, selected) if str(path).replace('\\', '/').split('/')[-1] == 'AndroidManifest.xml' else replace(result, outcome=ExecutionOutcome.NO_MATCH, evidence=(), witnesses=(), errors=())
        notes.append('Provider visibility, enabled state and effective read/write permissions are checked per declaration; this is not a complete access-control assessment.')
    if guidance:
        notes.append('The review label describes the evidence without asserting an unproven vulnerability.')
    if baseline.outcome != result.outcome:
        notes.append('Source-aware review changed the raw baseline outcome from {} to {}.'.format(baseline.outcome.value, result.outcome.value))
    return result, tuple(notes), guidance
