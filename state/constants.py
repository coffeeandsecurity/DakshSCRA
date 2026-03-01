## ----------- Banners | Credits | Console Output Decoration ----------- ##

AUTHOR_BANNER = '''
=============================================================
Daksh SCRA (Source Code Review Assist) - Beta v{version}

Developed by: Debasis Mohanty
Website     : https://www.coffeeandsecurity.com
Twitter     : @coffensecurity
Email       : d3basis.m0hanty@gmail.com
=============================================================
'''

def print_banner(version):
    print(AUTHOR_BANNER.format(version=version))
