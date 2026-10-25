"""Call-local review of native formatting APIs with stable source offsets."""
import re
from .adapters.tokenized import _lex

FORMAT_ARGUMENT = {'printf': 0, 'vprintf': 0, 'fprintf': 1, 'vfprintf': 1,
                   'sprintf': 1, 'vsprintf': 1, 'snprintf': 2, 'vsnprintf': 2}


def dynamic_format_calls(text, code):
    """Mask proven literal formats; unresolved arguments remain review leads.

    This does not infer attacker control, buffer capacity or format-type safety.
    Only the API name is masked so retained evidence keeps its source location.
    """
    # Literal examples are data, even when the file also has a real call.
    masked_data = list(text)
    pattern = r"\b(" + '|'.join(FORMAT_ARGUMENT) + r")\s*\("
    for match in re.finditer(pattern, text):
        if not re.search(pattern, code[match.start():match.end()]):
            start, end = match.span(1)
            masked_data[start:end] = ' ' * (end-start)
    text = ''.join(masked_data)
    tokens = _lex(text)
    offsets = [0] + [match.end() for match in re.finditer('\n', text)]
    masked = list(text)
    for index, token in enumerate(tokens[:-1]):
        if token.kind != 'identifier' or token.text not in FORMAT_ARGUMENT or tokens[index+1].text != '(':
            continue
        depth, arguments, current = 0, [], []
        closed = False
        for item in tokens[index+2:index+2002]:
            if item.kind == 'symbol':
                if item.text in {'(', '[', '{'}:
                    depth += 1
                elif item.text in {')', ']', '}'}:
                    if depth == 0:
                        if item.text == ')':
                            arguments.append(current)
                            closed = True
                        break
                    depth -= 1
                elif item.text == ',' and depth == 0:
                    arguments.append(current)
                    current = []
                    continue
            current.append(item)
        argument_index = FORMAT_ARGUMENT[token.text]
        if not closed or len(arguments) <= argument_index:
            continue
        argument = arguments[argument_index]
        # Adjacent ordinary string literals have one fixed format. Prefix/raw
        # literals and macros remain unresolved rather than assumed safe.
        fixed = bool(argument) and all(item.kind == 'string' and item.quote == '"' for item in argument)
        declaration = re.fullmatch(r'(?:const\s+)?(?:char|wchar_t)\s*\*\s*\w+', ' '.join(item.text for item in argument))
        if fixed or declaration:
            start = offsets[token.line-1] + token.column-1
            masked[start:start+len(token.text)] = ' ' * len(token.text)
    return ''.join(masked)
