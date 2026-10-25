"""Conservative known mobile-library boundaries; all argument may-flow remains.

These summaries establish neither input safety nor authorization. Callback and
unknown receiver behavior still requires normal project resolution.
"""
import re


def modeled_call(language, name, receiver_type, text, code):
    if language == 'javascript' and name.endswith('.create'):
        receiver = name.rsplit('.', 1)[0]
        for imported in re.finditer(r'\bimport\s*\{([^}]+)\}\s*from\s*["\']react-native["\']', text):
            if code[imported.start():imported.start()+6] != 'import':
                continue
            for binding in imported.group(1).split(','):
                parts = re.split(r'\s+as\s+', binding.strip())
                if parts[0] != 'StyleSheet' or parts[-1] != receiver:
                    continue
                escaped = re.escape(receiver)
                shadow = (r'\b(?:const|let|var|function|class)\s+'+escaped+r'\b|'
                          r'\b(?:const|let|var)\s*\{[^}]*\b'+escaped+r'\b|'
                          r'\bfunction\s*\w*\s*\([^)]*\b'+escaped+r'\b|'
                          r'\([^)]*\b'+escaped+r'\b[^)]*\)\s*=>|'
                          r'\b'+escaped+r'\s*(?:=>|=(?!=))')
                if not re.search(shadow, code):
                    return True
    if language in {'java','kotlin'}:
        imports={m.group(1) for m in re.finditer(r'\bimport\s+([\w.]+)\s*;',code)}
        method=name.rsplit('.',1)[-1]
        if name in {'Toast.makeText','android.widget.Toast.makeText'} and (
                name.startswith('android.') or 'android.widget.Toast' in imports):
            return True
        types={
            'View':('android.view.View',{'findViewById','setVisibility','setBackgroundColor','setBackgroundResource'}),
            'LayoutInflater':('android.view.LayoutInflater',{'inflate'}),
            'TextView':('android.widget.TextView',{'setText','setVisibility'}),
            'Button':('android.widget.Button',{'setText','setVisibility'}),
            'EditText':('android.widget.EditText',{'setText'}),
            'Map':('java.util.Map',{'put','get','containsKey'}),
            'HashMap':('java.util.HashMap',{'put','get','containsKey'}),
        }
        short=receiver_type.rsplit('.',1)[-1]
        if short in types:
            qualified,methods=types[short]
            return method in methods and (qualified in imports or receiver_type==qualified)
    if language == 'javascript' and name in {'useState','useEffect','useMemo','useCallback','useRef'}:
        for match in re.finditer(r'\bimport\s*\{([^}]+)\}\s*from\s*["\']react["\']',text):
            if code[match.start():match.start()+6]=='import' and re.search(r'\b'+name+r'\b(?!\s+as)',match.group(1)):
                return True
    return False
