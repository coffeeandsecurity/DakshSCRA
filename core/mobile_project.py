"""Inspectable mobile build, data-lifecycle and boundary review contracts.

Contracts report source evidence and unresolved requirements. They never claim
server authorization, shipped configuration or a cross-language call from names
alone. The file/byte budgets are part of the returned coverage state.
"""
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from core.mobile_model import (ANDROID, block_end, build_scope, load_plist,
                               module_namespace, preference_writes, sensitive_logs, views)
from utils.scan_scope import glob_source, walk_source

MAX_FILES = 5000
MAX_BYTES = 32 * 1024 * 1024
SOURCE_GLOBS = ('*.java', '*.kt', '*.kts', '*.gradle', '*.js', '*.jsx', '*.ts', '*.tsx', '*.mjs', '*.cjs',
                '*.swift', '*.m', '*.mm', '*.dart', '*.cs', '*.xml', '*.plist',
                '*.entitlements', '*.pbxproj', '*.strings', '*.php', '*.py', '*.go', '*.rb')


def signing_hits(path, text, code):
    """Direct release/debug references and aliases; unresolved DSL stays visible."""
    from core.rdl.mobile_review import gradle_variant
    aliases = set()
    for hit in re.finditer(r'\b(?:val|var|def)\s+(\w+)\s*=\s*signingConfigs\s*(?:\.\s*debug\b|\[\s*["\']debug["\']\s*\]|\.\s*(?:getByName|named)\s*\(\s*["\']debug["\']\s*\))', text):
        if code[hit.start():hit.start()+1].strip():
            aliases.add(hit.group(1))
    pattern = r'\bsigningConfig\s*(?:=\s*)?(?:signingConfigs\s*(?:\.\s*debug\b|\[\s*["\']debug["\']\s*\]|\.\s*(?:getByName|named)\s*\(\s*["\']debug["\']\s*\))|(?P<alias>\w+))'
    for hit in re.finditer(pattern, text):
        if not code[hit.start():hit.start()+1].strip() or (hit.group('alias') and hit.group('alias') not in aliases):
            continue
        if hit.group('alias'):
            from core.mobile_model import enclosing_blocks
            ancestors=enclosing_blocks(code,hit.start())
            assignments=[]
            for assignment in re.finditer(r'\b'+re.escape(hit.group('alias'))+r'\s*=\s*([^;\n{}]+)',text[:hit.start()]):
                if not code[assignment.start():assignment.start()+1].strip():
                    continue
                scope=enclosing_blocks(code,assignment.start())
                if ancestors[:len(scope)]==scope:
                    assignments.append(assignment)
            if assignments and not re.match(r'signingConfigs\s*(?:\.\s*debug\b|\[\s*["\']debug["\']\s*\]|\.\s*(?:getByName|named)\s*\(\s*["\']debug["\']\s*\))',assignments[-1].group(1)):
                continue
        variant = gradle_variant(code, text, hit.start())
        # Unrecognized inherited scope is not a proven release assignment.
        if variant == 'release':
            yield hit.start(), hit.end(), 'Release build references debug signing. Resolve CI overrides and inspect the distributed certificate; no private key value is recorded.'


def stream_hits(text, code):
    """Specific available-sized, unchecked one-shot provider stream reads."""
    for hit in re.finditer(r'\b(?:InputStream|var|val)\s+(\w+)\s*=\s*[^;\n]*\bopenInputStream\s*\([^;\n]+', code):
        receiver = hit.group(1)
        # Stop at the containing block; another method's read cannot satisfy it.
        from core.mobile_model import enclosing_blocks
        blocks = enclosing_blocks(code, hit.start())
        end = block_end(code, blocks[-1]) if blocks else len(code)
        tail = code[hit.end():end or len(code)]
        allocation = re.search(r'\b(?:byte\[\]|byte\s+\[\s*\])\s+(\w+)\s*=\s*new\s+byte\s*\[\s*'+re.escape(receiver)+r'\.available\s*\(\s*\)\s*\]', tail)
        if not allocation:
            continue
        read = re.search(r'(?m)^\s*'+re.escape(receiver)+r'\.read\s*\(\s*'+re.escape(allocation.group(1))+r'\s*\)\s*;', tail[allocation.end():])
        if read:
            yield hit.start(), hit.end()+allocation.end()+read.end(), 'Provider InputStream uses available() as total size and ignores a one-shot read count. Use bounded streaming, handle partial/null reads and close the stream on every path.'


class MobileProject:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.files = {}
        self.issues = []
        total = 0
        import fnmatch
        paths=[]
        discovered=0
        for directory,children,names in walk_source(self.root,followlinks=False):
            children[:]=sorted(name for name in children if name not in {'.git','node_modules','.gradle','build','Pods','venv','.venv'})
            for name in sorted(names):
                discovered+=1
                if any(fnmatch.fnmatch(name,pattern) for pattern in SOURCE_GLOBS):
                    paths.append(Path(directory)/name)
                if len(paths)>=MAX_FILES or discovered>=MAX_FILES*20:
                    self.issues.append('Mobile project discovery budget exceeded')
                    break
            if self.issues:
                break
        for path in paths:
            if len(self.files) >= MAX_FILES:
                self.issues.append('Mobile project file budget exceeded')
                break
            try:
                if self.root not in path.resolve().parents:
                    self.issues.append('Mobile source link escapes the selected root: '+str(path))
                    continue
                size = path.stat().st_size
                if size > 4*1024*1024 or total+size > MAX_BYTES:
                    self.issues.append('Mobile project byte budget excludes '+self.rel(path))
                    continue
                from utils.source_cache import read_source_text
                text = read_source_text(path,encoding='utf-8')
                total += size
                self.files[path.resolve()] = (text,) + views(path, text)
            except (OSError, UnicodeError) as exc:
                self.issues.append('Unreadable mobile source '+self.rel(path)+': '+str(exc))

    def rel(self, path):
        try:
            return Path(path).resolve().relative_to(self.root).as_posix()
        except ValueError:
            return str(path)

    def loc(self, path, text, offset=0):
        return dict(file=self.rel(path), line=text.count('\n',0,offset)+1,
                    build_scope=build_scope(path))

    def purpose_hits(self, path):
        """Correlate supported camera/library/location APIs with this plist."""
        try:
            data = load_plist(path)
        except (OSError, ValueError, ET.ParseError) as exc:
            return [], ['Cannot resolve privacy configuration: '+str(exc)]
        if build_scope(path) == 'test':
            return [], []
        requirements = {
            'NSCameraUsageDescription': r'\blaunchCamera\s*\(|\bUIImagePickerControllerSourceTypeCamera\b|\bAVCaptureDevice\s*\.\s*(?:requestAccess|default)\s*\(\s*(?:(?:for|mediaType)\s*:\s*)?(?:\.video|AVMediaTypeVideo)\b|\bAVCaptureDevice\s+(?:requestAccessForMediaType|defaultDeviceWithMediaType)\s*:\s*AVMediaTypeVideo\b|\bsourceType\s*=\s*\.camera\b',
            'NSPhotoLibraryUsageDescription': r'\b(?:PHPhotoLibrary\s*\.\s*requestAuthorization|ImagePicker\s*\.\s*openPicker)\s*\(',
            'NSLocationWhenInUseUsageDescription': r'\b(?:getCurrentPosition|watchPosition|requestWhenInUseAuthorization)\s*\(',
        }
        hits, incomplete = [], []
        for key, pattern in requirements.items():
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                continue
            generated = any(re.search(r'\bINFOPLIST_KEY_'+key+r'\s*=', comments)
                            for p,(text,comments,code) in self.files.items() if p.suffix == '.pbxproj')
            localized = any(re.search(r'["\']?'+key+r'["\']?\s*=\s*["\'][^"\']+',comments)
                            for p,(text,comments,code) in self.files.items() if p.name == 'InfoPlist.strings')
            if generated or localized:
                incomplete.append('Resolve selected target/localization for '+key)
                continue
            for source,(text,comments,code) in self.files.items():
                if source.suffix not in {'.js','.jsx','.ts','.tsx','.swift','.m','.mm'} or build_scope(source) in {'debug','test','androidTest'}:
                    continue
                selected_pattern = pattern
                if key == 'NSCameraUsageDescription' and source.suffix in {'.js','.jsx','.ts','.tsx','.mjs','.cjs'}:
                    aliases = []
                    for imported in re.finditer(r'\bimport\s*\{([^}]+)\}\s*from\s*["\']react-native-image-picker["\']', comments):
                        if code[imported.start():imported.start()+6] == 'import':
                            aliases.extend(re.findall(r'\blaunchCamera\s+as\s+([A-Za-z_$][\w$]*)', imported.group(1)))
                    if aliases:
                        selected_pattern += '|' + '|'.join(r'\b'+re.escape(alias)+r'\s*\(' for alias in aliases)
                for hit in re.finditer(selected_pattern, code):
                    hits.append(dict(key=key, source=self.loc(source,text,hit.start()),
                                     configuration=self.rel(path), state='missing_or_empty',
                                     assumptions=['Resolve active caller and final generated/localized plist; API-specific permission requirements apply.']))
        return hits, incomplete

    def backup_contracts(self, manifest):
        try:
            root = ET.fromstring(self.files[Path(manifest).resolve()][1])
        except (KeyError,ET.ParseError):
            return []
        app = root.find('application')
        if app is None or app.get(ANDROID+'allowBackup') == 'false':
            return []
        policies = []
        for attribute in ('fullBackupContent', 'dataExtractionRules'):
            reference = app.get(ANDROID+attribute)
            if reference == 'false':
                policies.append(dict(attribute=attribute, state='disabled', sections=[]))
                continue
            name = reference[5:]+'.xml' if reference and reference.startswith('@xml/') else None
            candidates = [p for p in self.files if p.name == name and p.parent.name == 'xml'] if name else []
            # Only the same module/source set is evidence for this manifest.
            candidates = [p for p in candidates if Path(manifest).parent in p.parents]
            if len(candidates) != 1:
                policies.append(dict(attribute=attribute,state='unresolved' if reference else 'platform_default',
                                     sections=[] if reference else [dict(kind=attribute+'-platform-default',includes=[],excludes=[])]))
                continue
            path = candidates[0]
            try:
                config = ET.fromstring(self.files[path][1])
                expected = 'full-backup-content' if attribute == 'fullBackupContent' else 'data-extraction-rules'
                if config.tag != expected:
                    policies.append(dict(attribute=attribute,state='unresolved',sections=[]))
                    continue
                sections = [config] if config.tag == 'full-backup-content' else list(config)
                section_items = [dict(kind=n.tag, origin='explicit_section',
                    includes=[dict(x.attrib) for x in n.findall('include')],
                    excludes=[dict(x.attrib) for x in n.findall('exclude')]) for n in sections]
                if config.tag == 'data-extraction-rules':
                    # Cloud and device-transfer rules are independent. An
                    # omitted mode retains defaults, not another mode's excludes.
                    for mode in ('cloud-backup', 'device-transfer'):
                        if not any(n.tag == mode for n in sections):
                            section_items.append(dict(kind=mode,origin='platform_default_missing_section',includes=[],excludes=[]))
                policies.append(dict(attribute=attribute,file=self.rel(path),state='source_configuration',sections=[
                    item for item in section_items]))
            except ET.ParseError:
                policies.append(dict(attribute=attribute,state='unresolved',sections=[]))
        contracts = []
        for path,(text,comments,code) in self.files.items():
            if path.suffix not in {'.java','.kt'}:
                continue
            module = next((p for p in Path(manifest).parents if (p/'build.gradle').is_file() or (p/'build.gradle.kts').is_file()),self.root)
            if module not in path.parents:
                continue
            stores = re.findall(r'\bgetSharedPreferences\s*\(\s*["\']([^"\']+)["\']', comments)
            for start,end,key in preference_writes(comments,code):
                # Multiple stores in the file cannot be assigned by proximity.
                store = stores[0]+'.xml' if len(set(stores)) == 1 else None
                for policy in policies:
                    for section in policy['sections']:
                        def covers(item):
                            return item.get('domain') == 'sharedpref' and (item.get('path') in {'.','./',''} or item.get('path') == store)
                        excluded = store is not None and any(covers(x) for x in section['excludes'])
                        included = not section['includes'] or (store is not None and any(covers(x) for x in section['includes']))
                        state = 'excluded' if excluded else 'potentially_included' if store and included else 'unresolved'
                        contracts.append(dict(kind='sensitive_store_backup',source=self.loc(path,text,start),key=key,
                            store=store,policy=policy.get('file'),section=section['kind'],state=state,
                            policy_origin=section.get('origin','platform_default'),
                            assumptions=['Source policies only; resolve OS/target SDK, selected resources, encryption, transport and backup/restore behavior.']))
        return contracts

    def report(self, evaluation_records=()):
        builds, lifecycle, bridges, endpoints, controls = [], [], [], [], []
        privacy, backup = [], []
        for path,(text,comments,code) in self.files.items():
            if path.suffix == '.java':
                from core.rdl.android_requests import credential_http_requests
                for start, end, detail in credential_http_requests(comments, code):
                    endpoints.append(dict(self.loc(path,text,start),kind='credential_http_request',
                        transport='http',state='source_review',detail=detail,
                        requirements=['Resolve the same parameter value, endpoint and queue submission',
                                      'Verify selected transport policy and release inclusion',
                                      'Backend authorization and actual interception remain unresolved']))
            if path.suffix in {'.js','.jsx','.ts','.tsx','.mjs','.cjs'}:
                from core.rdl.session_contracts import logout_contracts
                contracts, unknown = logout_contracts(self, path)
                lifecycle.extend(contracts)
                if unknown:
                    lifecycle.append(dict(file=self.rel(path),kind='logout_persistence_contract',state='unresolved',limitations=unknown))
            if path.name == 'AndroidManifest.xml':
                builds.append(dict(file=self.rel(path),build_scope=build_scope(path),namespace=module_namespace(path,self.root),state='source_configuration'))
                backup.extend(self.backup_contracts(path))
            if path.name == 'Info.plist':
                hits,unknown = self.purpose_hits(path)
                privacy.extend(hits)
                self.issues.extend(unknown)
            for start,end,detail in signing_hits(path,comments,code) if path.name in {'build.gradle','build.gradle.kts'} else ():
                builds.append(dict(self.loc(path,text,start),kind='release_debug_signing',state='source_configuration',detail=detail))
            if path.suffix in {'.js','.jsx','.ts','.tsx','.java','.kt','.swift','.dart','.cs'}:
                for start,end,key in preference_writes(comments,code):
                    lifecycle.append(dict(self.loc(path,text,start),kind='credential_storage',key=key,state='review_required'))
                for start,end,detail in sensitive_logs(comments,code):
                    lifecycle.append(dict(self.loc(path,text,start),kind='sensitive_logging',state='review_required',detail=detail))
                for hit in re.finditer(r'\b(?:SignOut|signOut|logout|purge|removeItem|clear)\s*\(', code):
                    from core.mobile_model import enclosing_blocks
                    blocks=enclosing_blocks(code,hit.start())
                    prefix=comments[blocks[-1] if blocks else 0:hit.start()]
                    cleared=bool(re.search(r'\bdispatch\s*\(\s*SetAuthUserToken\s*\(\s*["\']["\']\s*\)',prefix))
                    lifecycle.append(dict(self.loc(path,text,hit.start()),kind='cleanup_call',
                        state='caller_clears_auth_token' if cleared else 'caller_and_store_resolution_required',
                        assumptions=['A local cleanup call alone does not establish or disprove cleanup of other stores or server sessions.']))
                for hit in re.finditer(r'\b(?:SecureStore\.setItemAsync|Keychain\.setGenericPassword|SecureStorage(?:\.Default)?\.SetAsync|SecItemAdd|SecItemUpdate|(?:secureStorage|secure_storage)\.write)\s*\(',code):
                    lifecycle.append(dict(self.loc(path,text,hit.start()),kind='protected_store_operation',state='protection_and_lifetime_unresolved',
                        requirements=['Resolve exact store, value, access class and key policy','Verify lock state, backup/restore, reinstall and account change; a secure-storage API name alone is not proof of protection']))
                for hit in re.finditer(r'\b(?:onPause|onStop|onRestoreInstanceState|applicationDidEnterBackground|sceneDidEnterBackground|scenePhase|didEnterBackgroundNotification)\b',code):
                    lifecycle.append(dict(self.loc(path,text,hit.start()),kind='lifecycle_event',state='sensitive_value_effects_unresolved',
                        requirements=['Trace the same value/store to this event','Review background snapshots, cleanup, restore and cancellation without assuming that missing local cleanup means missing caller cleanup']))
                for hit in re.finditer(r'\bpersistReducer\s*\(',code):
                    lifecycle.append(dict(self.loc(path,text,hit.start()),kind='state_persistence',
                        state='auth_storage_review' if re.search(r'\bauthReducer\b',code) and 'AsyncStorage' in code else 'backing_store_unresolved',
                        assumptions=['Bind persisted reducers, transforms and backing store; do not infer credential contents from configuration alone.']))
                for hit in re.finditer(r'\b(?:NativeModules\.(\w+)\.(\w+)|MethodChannel\s*\(|invokeMethod\s*\(|@ReactMethod\b|addJavascriptInterface\s*\(|addScriptMessageHandler\s*[:(])', code):
                    bridges.append(dict(self.loc(path,text,hit.start()),kind='bridge_boundary',module=hit.group(1),method=hit.group(2),
                                        state='unresolved_cross_language_contract',requirements=['Resolve exact registration/export identity and call target','Verify argument schema, caller/origin policy, return and failure branches']))
                for hit in re.finditer(r'\b(?:fetch|axios\.(?:get|post|put|delete)|StringRequest|JsonObjectRequest|JsonArrayRequest)\s*\(', code):
                    end=block_end(code,hit.end()-1,'(',')')
                    body=comments[hit.end():min(end or hit.end()+1000,hit.end()+1000)]
                    # Credential values are never copied into contracts.
                    hosts=sorted(set(re.findall(r'https?://([A-Za-z0-9.-]+)',body)))
                    handler_names=set(re.findall(r'["\']([^"\'\s?]+\.(?:php|py|rb))',body))
                    handlers=[self.loc(p,source) for p,(source,_,_) in self.files.items() if p.name in {Path(n).name for n in handler_names}]
                    endpoints.append(dict(self.loc(path,text,hit.start()),kind='client_api_contract',hosts=hosts,
                                          source_handlers=handlers if len(handlers)==1 else [],
                                          binding_state='unique_source_handler_candidate' if len(handlers)==1 else 'backend_source_missing_or_ambiguous',
                                          object_id_fields=sorted(set(re.findall(r'["\']((?:user|student|teacher|account|record)_id)["\']',comments))),
                                          authentication='carrier_present_needs_binding' if re.search(r'\bAuthorization\b|\bBearer\b|getHeaders\s*\(',comments) else 'unresolved',
                                          server_authorization='not_evaluated',requirements=['Bind request method, destination, auth carrier and object ownership to backend handler when supplied']))
                for hit in re.finditer(r'\b(?:canOpenURL|checkSelfPermission|originWhitelist|onShouldStartLoadWithRequest|allowlist|whitelist)\b',code):
                    controls.append(dict(self.loc(path,text,hit.start()),kind='candidate_control',state='effectiveness_unresolved',
                                         requirements=['Same value and receiver','Rejects unsafe case before use on every supported path','Capability/parser checks alone are not authorization']))
                from core.mobile_model import url_guarded
                for hit in re.finditer(r'\bLinking\.openURL\s*\(',code):
                    end=block_end(code,hit.end()-1,'(',')')
                    expression=comments[hit.end():end-1] if end else ''
                    controls.append(dict(self.loc(path,text,hit.start()),kind='url_operation_contract',
                        state='modeled_positive_host_protocol_gate' if url_guarded(comments,code,hit.start(),expression) else 'rejecting_policy_not_established',
                        assumptions=['Supported local positive host/protocol branch only; type identity, redirects and platform behavior may require additional review.']))
        # Bind only exact module and method identities; ambiguous exports stay open.
        exports={}
        for path,(text,comments,code) in self.files.items():
            if path.suffix not in {'.java','.kt'}:
                continue
            module=re.search(r'\bgetName\s*\([^)]*\)\s*(?::\s*String\s*)?(?:\{\s*return\s+|=\s*)["\'](\w+)["\']',comments)
            if not module or not code[module.start():module.start()+1].strip():
                continue
            for method in re.finditer(r'@ReactMethod\s+(?:(?:public|private|protected|final|static|suspend)\s+)*(?:fun\s+|[\w<>?]+\s+)(\w+)\s*\(([^)]*)\)',comments):
                if not code[method.start():method.start()+1].strip():
                    continue
                exports.setdefault((module.group(1),method.group(1)),[]).append(dict(self.loc(path,text,method.start()),
                    parameters=[re.sub(r'\s+',' ',a.strip()) for a in method.group(2).split(',') if a.strip()]))
        for contract in bridges:
            matches=exports.get((contract['module'],contract['method']),[])
            if len(matches)==1:
                contract.update(state='resolved_source_contract',native_export=matches[0],
                    assumptions=['Exact source name binding only; verify package registration, selected native build, argument semantics and privilege checks.'])
        channels={}
        flutter_calls=[]
        for path,(text,comments,code) in self.files.items():
            bindings={}
            channel_names=[]
            for constructor in re.finditer(r'\bMethodChannel\s*\(',code):
                end=block_end(code,constructor.end()-1,'(',')')
                if not end:
                    continue
                names=re.findall(r'["\']([^"\']+)["\']',comments[constructor.end():end-1])
                if len(names)!=1:
                    continue
                channel_names.append(names[0])
                binding=re.search(r'\b(\w+)\s*=\s*(?:const\s+)?$',code[max(0,constructor.start()-100):constructor.start()])
                if binding:
                    bindings[binding.group(1)]=names[0]
            if path.suffix in {'.java','.kt'} and len(set(channel_names))==1 and 'setMethodCallHandler' in code:
                for method in re.finditer(r'\bcall\.method\s*(?:==\s*["\'](\w+)["\']|\.equals\s*\(\s*["\'](\w+)["\'])',comments):
                    channels.setdefault((channel_names[0],method.group(1) or method.group(2)),[]).append(self.loc(path,text,method.start()))
            if path.suffix=='.dart':
                for call in re.finditer(r'\b(\w+)\.invokeMethod(?:<[^>]+>)?\s*\(\s*["\'](\w+)["\']',comments):
                    if code[call.start():call.start()+1].strip() and call.group(1) in bindings:
                        flutter_calls.append(dict(self.loc(path,text,call.start()),kind='flutter_channel_contract',channel=bindings[call.group(1)],method=call.group(2)))
        for contract in flutter_calls:
            matches=channels.get((contract['channel'],contract['method']),[])
            contract.update(state='resolved_source_contract' if len(matches)==1 else 'unresolved_cross_language_contract',
                            native_export=matches[0] if len(matches)==1 else None,
                            requirements=['Exact source channel/method binding only','Verify selected registration, argument schema, authorization and error/cancellation branches'])
            bridges.append(contract)
        outcomes=Counter(r.get('v2_outcome','NOT_EVALUATED') for r in evaluation_records)
        return dict(schema_version=1,source_root=str(self.root),state='incomplete' if self.issues else 'source_review',
                    coverage=dict(files=len(self.files),file_budget=MAX_FILES,byte_budget=MAX_BYTES,limitations=sorted(set(self.issues)),
                                  retained_outcomes=dict(outcomes),not_evaluated='Absence of an evaluation is not NO_MATCH; build artifacts, runtime and backend enforcement remain unresolved.'),
                    builds=builds,privacy=privacy,backup=backup,lifecycle=lifecycle,bridges=bridges,api_contracts=endpoints,control_contracts=controls)


def project_for_review(root):
    """Cache only inside a scan snapshot; never retain a stale project globally."""
    from utils.source_cache import current_snapshot
    snapshot = current_snapshot()
    if snapshot is not None:
        if not hasattr(snapshot, '_mobile_projects'):
            snapshot._mobile_projects = {}
        key = str(Path(root).resolve())
        if key not in snapshot._mobile_projects:
            if len(snapshot._mobile_projects) >= 4:
                snapshot._mobile_projects.pop(next(iter(snapshot._mobile_projects)))
            snapshot._mobile_projects[key] = MobileProject(root)
        return snapshot._mobile_projects[key]
    return MobileProject(root)


def retained_outcomes(telemetry):
    """Aggregate persisted groups without decompressing every evidence block."""
    import sqlite3
    from core.rdl.result_store import database_path
    path=database_path(Path(telemetry))
    if not path.is_file():
        return {}
    connection=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        return dict(connection.execute('SELECT outcome,COUNT(*) FROM groups GROUP BY outcome'))
    finally:
        connection.close()


def write_review(root, destination, evaluation_records=(), evaluation_counts=None):
    report = MobileProject(root).report(evaluation_records)
    if evaluation_counts is not None:
        report['coverage']['retained_outcomes']=evaluation_counts
    path=Path(destination)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    import html
    parts=['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mobile Review Evidence</title><style>body{font:16px/1.5 system-ui;max-width:1100px;margin:32px auto;padding:0 20px;color:#20324b}article{border:1px solid #ced8e5;border-radius:8px;padding:16px;margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}h2{margin-top:32px}</style><h1>Mobile Review Evidence</h1><p>Source contracts connect build configuration, sensitive data and application boundaries. Confirm selected artifacts and active callers. Unresolved contracts are review questions, not confirmed vulnerabilities.</p>']
    labels=dict(coverage='Coverage and unresolved analysis',builds='Build configuration',privacy='Protected resource descriptions',backup='Sensitive storage and backup',lifecycle='Sensitive data and cleanup',bridges='Cross-language bridge contracts',api_contracts='Mobile and backend contracts',control_contracts='Control effectiveness')
    for key,title in labels.items():
        parts.append('<h2>'+title+'</h2>')
        records=report[key] if isinstance(report[key],list) else [report[key]]
        if not records:
            parts.append('<p>No supported source evidence recorded in this scope. This is not a safety verdict.</p>')
        for record in records:
            parts.append('<article><pre>'+html.escape(json.dumps(record,indent=2))+'</pre></article>')
    parts.append('</html>')
    path.with_suffix('.html').write_text('\n'.join(parts),encoding='utf-8')
    return report
