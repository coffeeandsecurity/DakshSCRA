"""Executable-language profiles for bounded project data-flow review.

These models identify review surfaces, not runtime reachability. Configuration
formats intentionally do not receive an executable-language adapter.
"""
import re

EXTENSIONS = {
    'javascript': ('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'),
    'java': ('.java', '.jsp'), 'kotlin': ('.kt', '.kts'),
    'csharp': ('.cs', '.cshtml', '.aspx', '.asax', '.svc'),
    'vb': ('.vb', '.asp'), 'go': ('.go',),
    'c': ('.c', '.h'), 'cpp': ('.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx', '.h'),
    'ruby': ('.rb', '.erb'), 'rust': ('.rs',), 'swift': ('.swift',),
    'objc': ('.m', '.mm'), 'dart': ('.dart',),
    'bash': ('.sh', '.bash', '.bsh'), 'powershell': ('.ps1', '.psm1'),
    'groovy': ('.groovy',), 'carbon': ('.carbon',),
}
INPUT = frozenset({'input.untrusted', 'input.untrusted-path', 'input.untrusted-url'})
# Expressions, including property/index access, rather than arbitrary variable names.
SOURCES = {
    'javascript': r'\b(?:getInitialURL|getInitialLink|getLaunchUrl|getIntent|getStringExtra|readline|prompt)\(|\b(?:event\.url|e\.target\.value|event\.target\.value|route\.(?:query|snapshot)|searchParams|document\.location|window\.location)\b|\b(?:req(?:uest)?|ctx|context|event)\.(?:query|body|params|headers|cookies|request|data)\b|\b(?:location\.(?:search|hash)|process\.argv|document\.cookie|route\.params)\b|\b(?:getStringExtra|getIntent|readline|prompt)\(',
    'java': r'\b(?:getParameter|getParameterValues|getHeader|getQueryString|getInputStream|getReader|getStringExtra|getExtras|getDataString|readLine)\(|\b(?:System\.getenv|args)\b',
    'kotlin': r'\b(?:savedStateHandle|navController\.currentBackStackEntry\.arguments|parameters\[)\b|\b(?:getParameter|getHeader|getStringExtra|getQueryParameter|receiveText|receiveParameters|receive|readLine)\(|\b(?:call\.(?:parameters|request)|intent\.(?:data|extras)|args)\b',
    'csharp': r'\b(?:[Rr]equest\.(?:Query|QueryString|Form|Body|Headers|Cookies|Params)|args|Environment\.GetEnvironmentVariable)\b|\b(?:ReadLine|GetStringExtra|GetQueryParameter)\(',
    'vb': r'\b(?:Request\.(?:QueryString|Form|Params|Cookies)|Request\(|Command\(|Console\.ReadLine\()',
    'go': r'\b(?:c|ctx|context)\.Query\(|\b(?:os\.Args|(?:r|req|request)\.(?:URL|Body|Form|PostForm|Header))\b|\b(?:r|req|request)\.(?:Cookie|Cookies)\(|\b(?:FormValue|PostFormValue|QueryParam|Param|GetHeader|GetString)\(',
    'c': r'\b(?:argv|getenv|gets|fgets|getline|read|recv)\b',
    'cpp': r'\b(?:argv|getenv|gets|fgets|getline|read|recv|cin|QLineEdit)\b|\b(?:text|readAll|queryItemValue)\(',
    'ruby': r'\b(?:params|ARGV|ENV|request\.(?:body|params|query_string|headers)|gets)\b',
    'rust': r'\b(?:env::args|env::var|std::env::args|std::env::var|read_line)\b',
    'swift': r'\b(?:textField\.text|url\.absoluteString|URLContexts)\b|\b(?:CommandLine\.arguments|ProcessInfo\.processInfo\.environment|url\.query|request\.(?:query|body)|textField\.text)\b|\b(?:readLine|valueForHTTPHeaderField)\(',
    'objc': r'\b(?:getenv|argv|userInfo|valueForHTTPHeaderField)\b|\b(?:request|url|textField)\.(?:query|text|body)\b',
    'dart': r'\b(?:getInitialUri|getInitialLink|readAsString)\(|\b(?:Platform\.environment|request\.(?:url|uri|body|queryParameters)|uri\.queryParameters|settings\.arguments|controller\.text|args)\b|\b(?:readLineSync|getInitialLink|getString)\(',
    'bash': r'\$(?:[1-9@*]|\{[1-9@*][^}]*\})|\b(?:read|readarray)\b',
    'powershell': r'\$(?:args|env:|Input|Request\b)|\bRead-Host\b',
    'groovy': r'\b(?:params|request\.(?:parameterMap|queryString)|getParameter|System\.getenv|args)\b',
    'carbon': r'\b(?:args|GetEnv|ReadLine)\b',
}
# Mobile IPC and native WebView bridges are untrusted entry boundaries even
# when another callback in the project has an origin or authorization guard.
SOURCES['java'] += r'|\b(?:getIntent|getData|getParcelableExtra|getSerializableExtra|getQueryParameter)\s*\(|\bmessage\.getData\s*\('
SOURCES['kotlin'] += r'|\b(?:getIntent|getData|getDataString|getParcelableExtra|getSerializableExtra|getExtras)\s*\('
SOURCES['swift'] += r'|\b(?:message\.body|navigationAction\.request\.url|userActivity\.webpageURL)\b'
SOURCES['objc'] += r'|\b(?:message\.body|userActivity\.webpageURL|URLContexts)\b'
# Explicit API families; a resolved application function overrides these heuristics.
SINKS = {
    'command.execution': {
        'javascript': r'(?:^|\.)(?:exec|execSync)$|^shell\.exec$',
        'java': r'(?:^|\.)(?:exec|ProcessBuilder)$', 'kotlin': r'(?:^|\.)(?:exec|ProcessBuilder)$',
        'csharp': r'(?:Process\.Start|StartProcess)$', 'vb': r'(?:Shell|Process\.Start)$',
        'go': r'(?:exec\.Command|exec\.CommandContext)$',
        'c': r'(?:^|\.)(?:system|popen|execl|execv)$', 'cpp': r'(?:^|::|\.)(?:system|popen|execl|execv|execle|execve|execlp|execvp|execvpe|CreateProcess(?:A|W)?|ShellExecute(?:Ex)?(?:A|W)?|WinExec|(?:g_)?spawn_command_line_(?:async|sync)|execute|startDetached)$',
        'ruby': r'(?:^|\.)(?:system|exec|spawn|popen)$',
        'rust': r'(?:Command::new|\.arg|\.args)$', 'swift': r'(?:system|popen|Process|\.run)$',
        'objc': r'(?:system|popen|launch|launchPath)$', 'dart': r'Process\.(?:run|runSync|start)$',
        'bash': r'^(?:eval|bash|sh|zsh|exec)$', 'powershell': r'^(?:Invoke-Expression|iex|Start-Process)$',
        'groovy': r'(?:^|\.)(?:execute|exec|ProcessBuilder)$', 'carbon': r'(?:System|Execute)$',
    },
    'sql.execution': {'*': r'(?:^|\.|::)(?:query|queryRaw|\$queryRawUnsafe|\$executeRawUnsafe|executeQuery|executeUpdate|rawQuery|execSQL|SqlCommand|ExecuteSqlRaw|ExecuteSqlCommand|Query|Exec|Raw|execute|exec_query|find_by_sql|select_all|sqlite3_exec|executeSql|raw|createQuery|createNativeQuery)$'},
    'filesystem.access': {'*': r'(?:^|\.|::)(?:open|fopen|readFile|readFileSync|writeFile|writeFileSync|readFileAsString|readAsString|readAsBytes|File|FileInputStream|FileOutputStream|OutputStreamWriter|ReadAllText|ReadAllBytes|WriteAllText|ReadFile|WriteFile|Open|OpenFile|read_to_string|file_get_contents|Get-Content|Set-Content|sendFile|send_file)$'},
    'network.outbound-request': {'*': r'(?:^|\.|::)(?:fetch|http\.get|http\.post|axios\.get|axios\.post|requests\.get|GetAsync|PostAsync|DownloadString|WebRequest\.Create|URL|Http\.Get|http\.Get|http\.Post|reqwest::get|URLSession|openUrl|HTTParty\.get|RestClient\.get|Invoke-WebRequest)$'},
    'dynamic.evaluation': {'*': r'(?:^|\.|::)(?:eval|import|Evaluate|evaluate|ExecuteScript|evaluateJavascript|evaluateJavaScript|loadHTMLString|Function)$'},
    'deserialization.object-construction': {'*': r'(?:^|\.|::)(?:Deserialize|DeserializeObject|readObject|Marshal\.load|YAML\.load|unsafe_load|unarchiveObjectWithData)$'},
    'output.html': {'*': r'(?:^|\.|::)(?:write|html|send|Html\.Raw|Write|render_template_string)$'},
}
PARAMETER_SOURCE = re.compile(r'@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|QueryParam|FormParam|PathParam|Body|Query|Param|Headers)\b|\[(FromBody|FromQuery|FromRoute|FromHeader|FromForm)\b|\b(?:web::(?:Query|Form|Path|Json)|Query<|Form<|Path<|Json<)')


def is_source(language, text):
    if language == 'go' and re.search(r'\.(?:Header|Form|PostForm)\.(?:Set|Add|Del)\s*\(|\.Body\.Close\s*\(', text):
        return False
    return bool(re.search(SOURCES[language], text, re.I if language in {'vb', 'powershell'} else 0))


SQL_APIS = {
    'javascript': r'(?:^|\.)(?:query|queryRaw|\$queryRawUnsafe|\$executeRawUnsafe|executeSql|raw)$',
    'go': r'(?:^|\.)(?:Query|QueryContext|Exec|ExecContext|Raw)$',
    'java': r'(?:^|\.)(?:executeQuery|executeUpdate|prepareStatement|createQuery|createNativeQuery|rawQuery|execSQL)$|(?:^|\.)(?:jdbcTemplate|namedParameterJdbcTemplate)\.(?:query|queryForList|queryForMap|queryForObject|update|execute|batchUpdate)$',
    'kotlin': r'(?:^|\.)(?:executeQuery|executeUpdate|prepareStatement|createQuery|rawQuery|execSQL|exec)$',
    'csharp': r'(?:^|\.)(?:SqlCommand|ExecuteSqlRaw|ExecuteSqlCommand|FromSqlRaw|ExecuteReader)$',
    'vb': r'(?:^|\.)(?:SqlCommand|ExecuteSqlRaw|ExecuteSqlCommand)$',
    'ruby': r'(?:^|\.)(?:execute|exec_query|find_by_sql|select_all|where)$',
    'rust': r'(?:^|\.|::)(?:query|execute|batch_execute|sql_query)$',
    'dart': r'(?:^|\.)(?:rawQuery|rawInsert|rawUpdate|execute|rawDelete)$',
    'swift': r'(?:^|\.)(?:execute|sqlite3_exec|NSPredicate)$',
    'objc': r'(?:^|\.)(?:executeQuery|sqlite3_exec|predicateWithFormat)$',
    'c': r'^sqlite3_exec$', 'cpp': r'(?:^|::|\.)(?:sqlite3_exec|exec|execute)$',
}
SINKS['platform.intent-launch'] = {language: r'(?:^|\.)(?:startActivity|startActivities|startService|startForegroundService|bindService|sendBroadcast|sendOrderedBroadcast)$' for language in ('java','kotlin')}
SINKS['navigation.redirect'] = {'python': r'^(?:flask|werkzeug\.utils|django\.shortcuts)\.redirect$'}
SINKS['platform.web-navigation'] = {
    'java': r'(?:^|\.)(?:loadUrl|postUrl)$', 'kotlin': r'(?:^|\.)(?:loadUrl|postUrl)$',
    'dart': r'(?:^|\.)(?:loadRequest|loadUrl)$',
}
SINKS['data.json-deserialization'] = {'csharp': r'(?:^|\.)DeserializeObject$'}
SINKS['deserialization.object-construction']['csharp'] = r'(?:^|\.)(?:Deserialize|readObject|unsafe_load|unarchiveObjectWithData)$'
SINKS['sql.execution'].update(SQL_APIS)
SINKS['sql.execution']['go'] = r'(?:^|\.)(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Select|SelectOne|SelectInt|SelectStr|SelectFloat|SelectNullInt|SelectNullStr)$'
SINKS['sql.execution']['csharp'] = r'(?:^|\.)(?:SqlQuery|ExecuteSqlCommand|ExecuteSqlRaw|ExecuteSqlInterpolated|FromSqlRaw|FromSqlInterpolated|SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar)$'


def sink_concepts(language, name):
    concepts = {concept for concept, profiles in SINKS.items()
                if re.search(profiles.get(language, profiles.get('*', r'(?!)')), name, re.I)}
    if 'command.execution' in concepts:
        concepts.discard('sql.execution')
    return concepts


def language_for_path(path):
    return next((language for language, extensions in EXTENSIONS.items() if path.suffix.lower() in extensions), None)


def project_mappings():
    """Supplemental semantic reviews run regardless of the selected framework."""
    rules = (
        'injection/command_injection', 'injection/sql_injection',
        'injection/cross_site_scripting', 'injection/code_injection',
        'security/path_traversal', 'security/server_side_request_forgery',
        'security/unsafe_deserialization',
    )
    mappings = {
        'project-flow/{}/{}'.format(language, rule.split('/')[-1]): {
            'v2_rule': ('rules/scanning/logic/rdl/v2/php/core/injection/code_injection.rdl' if rule == 'injection/code_injection'
                        else 'rules/scanning/logic/rdl/v2/common/core/' + rule + '.rdl'),
            'language': language, 'extensions': list(extensions), 'semantic_only': True,
        }
        for language, extensions in EXTENSIONS.items() for rule in rules
    }
    for language, extensions in EXTENSIONS.items():
        for kind in ('intent_redirection_flow','webview_navigation_flow'):
            if language not in ({'java','kotlin'} if kind == 'intent_redirection_flow' else {'java','kotlin','dart'}):
                continue
            mappings['project-flow/{}/{}'.format(language,kind)] = dict(
                v2_rule='rules/scanning/logic/rdl/v2/mobile/android/core/platform/'+kind+'.rdl',
                language=language,extensions=list(extensions),semantic_only=True)
    from .security_operations import MASS_APIS, HEADER_APIS, KEY_APIS
    models = dict(EXTENSIONS, python=('.py',), php=('.php',))
    for kind, profiles in (('bulk_binding_flow', MASS_APIS), ('origin_response_flow', HEADER_APIS),
                           ('literal_key_fallback_flow', KEY_APIS)):
        for language in profiles:
            mappings['project-flow/{}/{}'.format(language, kind)] = dict(
                v2_rule='rules/scanning/logic/rdl/v2/common/core/security/'+kind+'.rdl',
                language=language, extensions=list(models[language]), semantic_only=True)
    return mappings

# Exact output-encoding API summaries. Project definitions override these names.
HTML_ENCODERS = {
    'javascript': {'he.escape', 'he.encode'},
    'java': {'HtmlUtils.htmlEscape', 'StringEscapeUtils.escapeHtml4', 'Encode.forHtml'},
    'kotlin': {'HtmlUtils.htmlEscape', 'StringEscapeUtils.escapeHtml4', 'Encode.forHtml'},
    'csharp': {'HttpUtility.HtmlEncode', 'WebUtility.HtmlEncode'},
    'vb': {'HttpUtility.HtmlEncode', 'WebUtility.HtmlEncode'},
    'go': {'html.EscapeString', 'template.HTMLEscapeString'},
    'ruby': {'ERB::Util.html_escape', 'CGI.escapeHTML'},
}
