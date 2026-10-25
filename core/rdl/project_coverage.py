"""Audit registered platforms/frameworks against executable project models."""
import xml.etree.ElementTree as ET
from .portable_profiles import EXTENSIONS

CONFIGURATION = {
    'dockerfile': 'Container build instructions; configuration review, not an application call graph.',
    'terraform': 'Declarative infrastructure; configuration review, not an application call graph.',
    'kubernetes': 'Declarative workload manifests; configuration review, not an application call graph.',
}


def project_coverage(root):
    models = dict(EXTENSIONS, python=('.py',), php=('.php',))
    from .security_operations import MASS_APIS, HEADER_APIS, KEY_APIS
    platforms, failures = {}, []
    for rule in ET.parse(root / 'rules/scanning/rulesconfig.xml').getroot():
        name=rule.findtext('platform')
        patterns={item.strip() for item in (rule.findtext('platform_ftypes') or '').split(',')}
        languages=sorted(language for language,extensions in models.items()
                         if any('*'+extension in patterns for extension in extensions))
        platforms[name]=dict(languages=languages, frameworks=[],
                             scope='bounded project flow' if languages else 'configuration review',
                             limitation=CONFIGURATION.get(name,''))
        platforms[name]['security_models'] = {
            'origin_response_flow': sorted(set(languages).intersection(HEADER_APIS)),
            'bulk_binding_flow': sorted(set(languages).intersection(MASS_APIS)),
            'literal_key_fallback_flow': sorted(set(languages).intersection(KEY_APIS)),
            'authorization_context': languages,
            'tenant_isolation': 'custom application invariant required',
        }
        if not languages and name not in CONFIGURATION:
            failures.append('Registered platform has no project-flow model or configuration classification: '+name)
    for framework in ET.parse(root / 'rules/scanning/frameworkconfig.xml').getroot():
        name,platform=framework.findtext('name'),framework.findtext('platform')
        if platform not in platforms:failures.append('Framework has unknown platform: '+name)
        else:platforms[platform]['frameworks'].append(name)
    return dict(passed=not failures,failures=failures,platforms=platforms,
                executable_languages=sorted(models),
                limitations=['Framework rows inherit the listed source-language models; they do not promise every framework API or runtime dispatch mechanism.',
                             'Security-model entries list registered operation families, not exhaustive language/framework coverage.',
                             'Authorization declarations and field policy markers never automatically suppress candidates.',
                             'Tenant isolation and resource ownership require explicit application invariants; configuration scopes do not receive executable models.',
                             'Cross-language FFI, generated code, reflection, dynamic loading, object heap aliases and asynchronous dispatch require manual review.'])
