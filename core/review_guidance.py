"""Separate implementation verification from security review of source leads."""
import re

# Each profile states a protection to verify and an exploitation question.
# Selection changes explanatory text only; rule predicates and verdicts are untouched.
PROFILES = (
    (r'unrestricted select|select \*|wildcard',
     'database projection',
     'Check whether each query selects only the columns required by its caller, limits returned rows where appropriate, and enforces the intended record-access policy. A WHERE clause or wildcard projection alone does not establish injection or unauthorized access.',
     'Determine whether the query exposes columns or records to a caller who should not receive them. Inspect result mapping, the recipient and record-level access checks; assess query manipulation separately from data minimization.'),
    (r'sql|database quer|jdbc|dapper', 'SQL query handling',
     'Check whether data values are bound to the exact command by the driver or ORM, and dynamic identifiers or sort directions come from a fixed mapping. Verify query construction and parameter bindings at this operation; unrelated safe queries do not protect it.',
     'Trace caller-controlled and stored values into the final query. Determine whether they can change SQL structure, which execution path reaches the database, and what records or operations the connection permits. Verify bindings and access controls on this exact statement.'),
    (r'command|shell|process.*exec', 'process execution',
     'Check whether executable selection is fixed or allowlisted, arguments are passed separately as data, and command construction avoids interpreter syntax. Verify the effective environment, working directory and process privileges.',
     'Determine whether a caller can influence the executable, interpreter text, arguments or environment. Trace the reachable process call and assess whether quoting, argument separation and allowlists prevent command or option injection under the actual runtime.'),
    (r'deserial|object injection|unsafe loader', 'deserialization',
     'Check whether the loader accepts data-only input, restricts object/type construction, and bounds input size and nesting. Verify the actual parser configuration and allowed types at the matched call.',
     'Identify who can supply the serialized payload and whether reachable types, callbacks or parser features can trigger unwanted behavior. Verify effective type restrictions, payload integrity checks and resource limits; nearby safe parsers do not mitigate this call.'),
    (r'path traversal|file inclusion|file.*(?:write|read|access|copy)|directory|filesystem', 'file access',
     'Check whether user-selected paths are canonicalized and constrained to the intended directory, with filename/type policy and least-privilege access. Path joining, trimming or appending an extension does not establish containment.',
     'Trace caller-controlled and stored path components to reads, writes, copies or includes. Assess rooted paths, traversal, links, overwrite behavior and effective filesystem permissions; verify that containment checks apply to the final destination.'),
    (r'ssrf|server.side request|outbound|httpclient|webrequest', 'outbound requests',
     'Check whether outbound schemes, hosts, ports and resolved addresses are restricted for the operation. Verify redirects, DNS changes, credentials and network access policy rather than trusting a URL-format check.',
     'Determine whether a caller can select an unintended recipient or reach private services through redirects or name resolution. Trace the effective request destination and assess the application credentials, response exposure and egress restrictions.'),
    (r'xss|cross.site script|html|response\.write|php_self|encoding|output.*render', 'rendered output',
     'Check whether each output uses encoding appropriate to its HTML, attribute, script or URL context, and deliberately accepted rich content passes through a maintained sanitizer. Verify that safe-marking APIs do not bypass these protections.',
     'Trace attacker-controlled data to the actual rendering context and intended victim. Assess whether executable browser content can survive the effective encoding or sanitizer; verify reachability, origin, user interaction and relevant browser protections.'),
    (r'jwt|token.policy|claims.*valid', 'token verification',
     'Check whether the trusted verifier enforces signature, algorithm, issuer, audience and lifetime policy before claims influence privileges. Verify key selection and failure paths at the actual authentication boundary.',
     'Determine whether altered, expired or wrongly scoped tokens can reach a protected operation. Trace claims through verification and authorization, including upstream middleware and alternate paths; parsing alone does not prove validation or a bypass.'),
    (r'password|credential|secret|private.key|access.key', 'credential handling',
     'Check whether credentials are protected for their purpose: adaptive salted password verification, appropriate secret storage and access control, or protected key handling. Distinguish an actual credential value from labels, placeholders and public configuration.',
     'Identify the credential material, its recipient and who can read, substitute or misuse it. Trace authentication or cryptographic use and assess realistic exposure, privileges and effective storage controls; a password-related name alone is insufficient evidence.'),
    (r'\b(?:error|exception|stack.trace|log|logging|debug information)\b', 'diagnostic output',
     'Check whether user-visible errors are generic and sensitive fields are redacted before logging. Verify production configuration, diagnostic recipients, log access and retention. A try/catch block is not protection if it displays detailed exceptions.',
     'Trace exception details or sensitive values to their output destination. Determine whether an unintended reader can trigger or obtain paths, secrets or implementation details, and assess their usefulness to an attack; restricted internal logging differs from user-facing disclosure.'),
    (r'cors|origin|csrf|cross.site request', 'cross-origin operations',
     'Check whether origin and credential policies are narrowly scoped and state-changing operations verify the required request integrity controls. Verify the deployed middleware and route-specific exceptions.',
     'Determine whether an untrusted origin can read protected responses or induce a privileged state change. Assess credentials, browser enforcement, accepted methods/content types and effective origin or request-token checks on the reachable route.'),
    (r'authoriz|tenant|permission|bulk.bind|mass.assign|access control', 'resource authorization',
     'Check whether identity, role, tenant and ownership checks govern every sensitive read or write at the trusted boundary. Verify field allowlists and server-owned fields where objects are bound from caller input.',
     'Assess whether an unauthenticated or lower-privilege caller can access another resource, cross a tenant boundary or set a protected field. Trace alternate entry points and effective policy enforcement; a missing local check may be supplied by verified middleware.'),
    (r'authentic|session|login|logout|captcha|multi.factor', 'authentication and session handling',
     'Check whether the trusted identity verifier, session lifecycle and abuse controls apply to the operation, including failure and recovery paths. Verify that success is based on validated identity evidence rather than UI state or client input.',
     'Determine whether an attacker can impersonate a user, reuse or substitute a session, bypass an identity challenge or obtain unintended privileges. Trace reachable success/failure paths and verify effective middleware, session invalidation and abuse controls.'),
    (r'crypto|cipher|hash|random|nonce|tls|ssl|certificate|cleartext|http communication', 'cryptography and transport',
     'Check whether the algorithm and transport policy suit the protected data, keys and nonces are handled safely, and certificate/hostname verification remains effective. Distinguish security-sensitive use from checksums, examples and public identifiers.',
     'Establish the protected asset, attacker access and deployed protocol or cryptographic parameters. Assess whether prediction, key exposure, interception or verification bypass is feasible with the effective controls; an algorithm name alone is not a vulnerability.'),
    (r'eval|code execution|dynamic.evaluat|template.*inject|regex|regular.expression', 'interpreted content',
     'Check whether externally influenced text remains data rather than executable syntax. Verify fixed operation selection, parser/interpreter restrictions and resource limits at the matched evaluation.',
     'Trace attacker influence into evaluated expressions, templates or patterns and assess reachable code execution or resource exhaustion. Verify actual interpreter behavior, input constraints and failure paths before claiming an exploit.'),
    (r'upload|image.*input', 'file ingestion',
     'Check whether uploaded or selected content is validated by actual type, bounded in size, stored under a generated name and kept outside executable locations. Verify destination containment and access policy.',
     'Determine whether a caller can choose content, filename or destination that permits execution, overwrite, unintended access or resource exhaustion. Verify content validation, storage behavior and the route by which other users consume the file.'),
    (r'backdoor|monkey.patch|security.bypass|unsafe|memory|buffer', 'sensitive implementation behavior',
     'Check whether the matched operation has explicit input, ownership and lifecycle constraints, bounded resource use and a documented security purpose. Verify effective guards on all relevant paths.',
     'Identify the caller-controlled state and reachable sensitive operation, then assess the specific unintended behavior and required privileges. Verify guards and runtime prerequisites; a suspicious API or marker alone does not establish exploitation.'),
    (r'ipv4|ipv6|address|endpoint|url|route|api|model|todo|module|configuration|manifest', 'review surface',
     'Check whether this construct represents an actual input, recipient, configuration or protected operation, and whether its access policy is implemented. Distinguish code behavior from version metadata, documentation, labels and examples.',
     'Locate the real trust boundary behind this marker and determine whether an attacker can reach or influence it. Trace the effective data use and controls; record a review surface rather than a vulnerability when no unsafe behavior is established.'),
)


def _authored(text, marker):
    text = str(text or '')
    if marker in text:
        text = text.split(marker, 1)[1]
    return text.strip()


def clean_guidance(text):
    text = str(text or '').replace('—', '. ').replace('–', '-').replace(';', '.')
    text = text.replace('This can be confirmed as an issue when the matched path is reachable and required controls are missing, weak, or inconsistent.', '')
    text = text.replace('Verify the exact source, operation and applicable controls. This is a review candidate, not a confirmed vulnerability.', '')
    text = text.replace('Recommended actions:', 'Implementation checks:').replace('Additional implementation details to verify:', 'Implementation checks:')
    text = text.replace('Review steps:', 'Exploitability review:')
    text = re.sub(r'(?<=\. )([a-z])', lambda match: match[1].upper(), text)
    text = re.sub(r'[ \t]+', ' ', text)
    return re.sub(r'\n{3,}', '\n\n', text).strip()


def audience_guidance(title, developer='', reviewer='', category=''):
    """Present concrete implementation checks and security review questions."""
    text = f'{title} {category}'.lower().replace('_', ' ').replace('-', ' ')
    _, subject, dev, rev = next((profile for profile in PROFILES if re.search(profile[0], text)),
        ('', 'the matched implementation',
         'Check the protection at this operation and its failure path. Inspect the implementation and configuration before recommending a change.',
         'Identify who controls the input and how it reaches the operation. Verify the relevant controls and record what remains unresolved.'))
    developer = _authored(developer, 'Rule-specific protection to verify before changing code:')
    reviewer = _authored(reviewer, 'Rule-specific review context:')
    def combine(intro, detail):
        intro, detail = clean_guidance(intro), clean_guidance(detail)
        if detail.startswith(intro):
            detail = detail[len(intro):].strip()
        if not detail:
            return intro
        # Keep authored instructions, removing a repeated recommendation when
        # the same sentence is used as both summary and numbered action.
        detail = re.sub(r'(?m)^1\. (.+)$', lambda m: '' if m[1] in detail[:m.start()] else m[0], detail)
        detail = re.sub(r'Implementation checks:\s*(?=\Z)', '', detail).strip()
        return intro + ('\n\n' + detail if detail else '')
    return combine(dev, developer), combine(rev, reviewer)
