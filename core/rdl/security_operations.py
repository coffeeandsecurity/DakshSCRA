"""Argument-specific security operations shared by executable adapters.

These are review models, not assertions about framework configuration or
runtime access. Local application definitions take precedence in the resolver.
"""
import ast
import re


CORS = 'web.origin-response'
MASS = 'model.bulk-binding'
KEY = 'crypto.key-material'
FALLBACK = 'secret.literal-key-fallback'
ENCODERS = {
    'csharp': r'^(?:System\.Text\.)?Encoding\.(?:UTF8|ASCII|Unicode)\.GetBytes$',
    'java': r'(?:^|\.)getBytes$', 'kotlin': r'(?:^|\.)(?:getBytes|toByteArray)$',
    'javascript': r'^Buffer\.from$', 'dart': r'^utf8\.encode$',
    'rust': r'(?:^|\.)(?:as_bytes|to_string)$',
}

# Exact operation families. Broad names such as create/update/sign are not
# sufficient evidence of an ORM, cryptographic operation or response header.
MASS_APIS = {
    'javascript': r'(?:^|\.)(?:Object\.assign|mongoose\.Document\.set|prisma\.\w+\.(?:create|update)|sequelize\.\w+\.(?:create|update))$',
    'java': r'(?:^|\.)(?:BeanUtils\.copyProperties|BeanUtilsBean\.copyProperties|WebDataBinder\.bind)$',
    'kotlin': r'(?:^|\.)(?:BeanUtils\.copyProperties|BeanUtilsBean\.copyProperties|WebDataBinder\.bind)$',
    'csharp': r'(?:^|\.)(?:TryUpdateModelAsync|TryUpdateModel|UpdateModel|PopulateObject)$',
    'vb': r'(?:^|\.)(?:TryUpdateModelAsync|TryUpdateModel|UpdateModel|PopulateObject)$',
    'ruby': r'(?:^|\.)(?:assign_attributes|update_attributes)$',
    'php': r'(?:->|::)(?:fill|forceFill|setAttributes)$',
    'python': r'(?:^|\.)(?:bulk_update_mappings|bulk_insert_mappings)$',
}
KEY_APIS = {
    'javascript': ((r'(?:^|\.)(?:jwt|jsonwebtoken)\.(?:sign|verify)$', (1,)),
                   (r'(?:^|\.)(?:crypto\.)?createHmac$', (1,)),
                   (r'(?:^|\.)(?:crypto\.)?createCipheriv$', (1,))),
    'java': ((r'(?:^|\.)(?:SecretKeySpec|SymmetricSecurityKey)$', (0,)),),
    'kotlin': ((r'(?:^|\.)(?:SecretKeySpec|SymmetricSecurityKey)$', (0,)),),
    'csharp': ((r'(?:^|\.)(?:SymmetricSecurityKey|HMACSHA256|HMACSHA384|HMACSHA512)$', (0,)),),
    'vb': ((r'(?:^|\.)(?:SymmetricSecurityKey|HMACSHA256|HMACSHA384|HMACSHA512)$', (0,)),),
    'go': ((r'(?:^|\.)(?:hmac\.New)$', (1,)), (r'(?:^|\.)aes\.NewCipher$', (0,))),
    'python': ((r'(?:^|\.)(?:jwt\.(?:encode|decode))$', (1,)),
               (r'^hmac\.new$', (0,)),
               (r'(?:^|\.)(?:cryptography\.fernet\.)?Fernet$', (0,))),
    'php': ((r'^(?:hash_hmac)$', (2,)),
            (r'^(?:openssl_encrypt|openssl_decrypt)$', (2,)),
            (r'(?:^|\\)(?:JWT)::(?:encode|decode)$', (1,))),
    'ruby': ((r'^(?:JWT\.(?:encode|decode))$', (1,)),
             (r'^OpenSSL::HMAC\.(?:digest|hexdigest)$', (1,))),
    'rust': ((r'(?:^|::)(?:EncodingKey|DecodingKey)::from_secret$', (0,)),),
    'swift': ((r'(?:^|\.)(?:SymmetricKey)$', (0,)),),
    'objc': ((r'^CCHmac$', (1,)),),
    'dart': ((r'(?:^|\.)(?:Hmac)$', (1,)),),
    'c': ((r'^HMAC$', (1,)), (r'^EVP_(?:Encrypt|Decrypt)Init_ex$', (3,))),
    'cpp': ((r'(?:^|::)HMAC$', (1,)), (r'(?:^|::)EVP_(?:Encrypt|Decrypt)Init_ex$', (3,))),
    'groovy': ((r'(?:^|\.)(?:SecretKeySpec)$', (0,)),),
}
HEADER_APIS = {
    'javascript': r'(?:^|\.)(?:setHeader|header|set)$',
    'java': r'(?:^|\.)(?:setHeader|addHeader)$',
    'kotlin': r'(?:^|\.)(?:setHeader|addHeader|append)$',
    'csharp': r'(?:^|\.)(?:Append|Add|Set)$',
    'vb': r'(?:^|\.)(?:AddHeader|Append|Add|Set)$',
    'go': r'(?:^|\.)(?:Set|Add)$',
    'ruby': r'(?:^|\.)(?:set_header)$',
    'python': r'(?:^|\.)(?:headers\.(?:set|add)|set_header)$',
    'php': r'^(?:header)$|(?:->)(?:header|withHeader)$',
    'rust': r'(?:^|\.)(?:insert_header|append_header|header)$',
    'swift': r'(?:^|\.)(?:setValue|addValue)$',
    'dart': r'(?:^|\.)(?:set|add)$',
}


def operation_arguments(language, name, literals=(), argument_count=None, argument_labels=()):
    """Return concept -> relevant positional arguments; ignore other arguments."""
    result = {}
    flags = re.I if language in {'vb', 'php', 'powershell'} else 0
    if language in ENCODERS and re.search(ENCODERS[language],name):
        result['data.encoding-transform']=(0,)
    if language in MASS_APIS and re.search(MASS_APIS[language], name, flags):
        # BeanUtils.copyProperties(source, target) differs from PHP model binding.
        result[MASS] = (1,) if language == 'python' or name.endswith('Object.assign') else (0,)
        if name.endswith('Object.assign') and argument_count is not None:
            result[MASS] = tuple(range(1,argument_count))
        if language in {'java','kotlin'} and name.endswith('BeanUtils.copyProperties'):
            result[MASS] = (1,) if name.startswith(('org.apache.commons.beanutils.','org.apache.commons.beanutils2.')) else (0,) if name.startswith('org.springframework.beans.') else (0,1)
        elif language in {'java','kotlin'} and name.endswith('BeanUtilsBean.copyProperties'):
            result[MASS] = (1,)
    for pattern, positions in KEY_APIS.get(language, ()):
        if re.search(pattern, name, flags):
            if language == 'swift' and argument_labels and argument_labels[0] != 'data':
                continue
            result[KEY] = positions
    if language in HEADER_APIS and re.search(HEADER_APIS[language], name, flags):
        for position, value in literals:
            if isinstance(value, str) and value.casefold() == 'access-control-allow-origin':
                result[CORS] = (0,) if language == 'swift' or language == 'rust' and name.endswith(('insert_header','append_header')) else (1,)
            elif language == 'php' and name.lower() == 'header' and isinstance(value, str) and value.casefold().startswith('access-control-allow-origin:'):
                result[CORS] = (0,)
    return result


def token_arguments(tokens, spans):
    """Expose literal header names without treating strings as executable code."""
    result=[]
    for position,(first,end) in enumerate(spans):
        if first+2 < end and tokens[first].kind == 'identifier' and tokens[first+1].text == ':':
            first+=2
        if first < end and tokens[first].kind == 'string':
            result.append((position,tokens[first].text))
        elif first+1 < end and tokens[first].text == '(' and tokens[first+1].kind == 'string':
            result.append((position,tokens[first+1].text))
    return tuple(result)


def token_labels(tokens, spans):
    return tuple(tokens[first].text if first+1 < end and tokens[first].kind=='identifier'
                 and tokens[first+1].text==':' else '' for first,end in spans)


def python_operations(node, name):
    if name.startswith('<local>.'):
        return {},set()
    literals = tuple((i, value.value) for i, value in enumerate(node.args)
                     if isinstance(value, ast.Constant))
    operations = operation_arguments('python', name, literals)
    positions = {i for values in operations.values() for i in values}
    if KEY in operations:
        positions.update({'key', 'secret'})
    if MASS in operations:
        positions.add('mappings')
    return operations, positions


def python_fallback(node, aliases=None):
    """Recognize an explicit literal fallback, not an arbitrary nearby secret."""
    def environment(value):
        def name(value):
            return value.id if isinstance(value,ast.Name) else name(value.value)+'.'+value.attr if isinstance(value,ast.Attribute) else ''
        if not isinstance(value,ast.Call):return False
        raw=name(value.func)
        first,dot,rest=raw.partition('.')
        resolved=(aliases or {}).get(first,first)+(dot+rest if dot else '')
        return first in (aliases or {}) and resolved in {'os.getenv','os.environ.get'}
    literal = lambda value: isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)) and bool(value.value)
    if environment(node):
        return len(node.args) > 1 and literal(node.args[1]) or any(kw.arg == 'default' and literal(kw.value) for kw in node.keywords)
    return isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) and len(node.values) == 2 and environment(node.values[0]) and literal(node.values[1])


def token_environment(tokens):
    words = ''.join(t.text if t.kind != 'string' else '<literal>' for t in tokens)
    return bool(re.search(r'(?:getenv|GetEnvironmentVariable|System\.getenv|os\.Getenv|process\.env|Platform\.environment|env::var|ENV\[|ProcessInfo\.processInfo\.environment)', words))


def token_fallback(tokens):
    """Conservative same-expression environment/default association."""
    if not token_environment(tokens):
        return False
    # Require the fallback operator immediately followed by a nonempty literal.
    for index, token in enumerate(tokens):
        if token.kind == 'string' and token.text and index:
            prefix = ''.join(t.text for t in tokens[max(0, index - 2):index])
            if prefix.endswith(('??', '||', '?:', ':-', 'or')):
                return True
            if prefix.endswith('unwrap_or('):
                return True
            if index > 1 and tokens[index-1].text == ':' and any(t.text == '?' for t in tokens[:index-1]):
                return True
    return False
