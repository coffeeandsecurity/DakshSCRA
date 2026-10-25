"""Token-level evidence for explicit typed token-policy initializers."""
from .ast import EntityType


def token_policy_settings(walker):
    tokens = walker.tokens
    imports = set()
    for index, token in enumerate(tokens):
        if token.kind == 'identifier' and token.text == 'using':
            end = next((j for j in range(index + 1, min(index + 20, len(tokens)))
                        if tokens[j].text == ';'), None)
            if end is not None:
                imports.add(''.join(t.text for t in tokens[index + 1:end]
                                   if t.kind != 'string'))
    local_type = any(t.text == 'class' and index + 1 < len(tokens)
                     and tokens[index + 1].text == 'TokenValidationParameters'
                     for index, t in enumerate(tokens))
    properties = {'ValidateIssuer', 'ValidateAudience', 'ValidateLifetime',
                  'ValidateIssuerSigningKey', 'RequireSignedTokens'}
    for index, token in enumerate(tokens):
        if token.kind != 'identifier' or token.text != 'TokenValidationParameters':
            continue
        start = max(0, index - 8)
        prefix = ''.join(t.text for t in tokens[start:index + 1])
        explicit = prefix.endswith('newMicrosoft.IdentityModel.Tokens.TokenValidationParameters')
        imported = (index > 0 and tokens[index - 1].text == 'new'
                    and 'Microsoft.IdentityModel.Tokens' in imports and not local_type)
        if not (explicit or imported):
            continue
        opening = index + 1
        if opening in walker.pairs and tokens[opening].text == '(':
            opening = walker.pairs[opening] + 1
        if opening not in walker.pairs or tokens[opening].text != '{':
            continue
        for first, end in walker.segments(opening + 1, walker.pairs[opening]):
            field = tokens[first:end]
            if (len(field) == 3 and field[0].kind == 'identifier'
                    and field[0].text in properties and field[1].text == '='
                    and field[2].kind == 'identifier' and field[2].text == 'false'):
                walker.node(first, field[0].text, 'token-policy-setting',
                            {'config.security-control', 'config.insecure', 'config.jwt-validation-disabled'},
                            EntityType.CONFIGURATION_ENTRY,
                            {'setting': field[0].text, 'value': False,
                             'configured_type': 'Microsoft.IdentityModel.Tokens.TokenValidationParameters'})
