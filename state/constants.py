import os

from utils.config_utils import get_tool_version

version = get_tool_version()

## ----------- Banners | Credits | Console Output Decoration ----------- ##

author = f'''
=============================================================
DakshSCRA  (Source Code Review Assist) - Beta v{version}

Developed by: Debasis Mohanty
Website     : https://www.coffeeandsecurity.com
Twitter     : @coffensecurity
Email       : d3basis.m0hanty@gmail.com
=============================================================
'''


# NOT-IN-USE - To be used later after some improvements
def print_banner():
    starfish = r'''                                                                                          
                -##*                                                                      
               :#+=*-                                                                     
               *-#=-#                                                                     
               %:#+:%.                                                                    
               @-#*:++       .==-                                                         
   .:::.      .#+#%:-%:    =+=::%-                                                        
 .#*+*#####***#***@:--#+=++-:-*#*+                                                        
 .%#**************%=----::-=##==%.                                                        
   =++=--=+**##%####=---+*#*=+##:  ::::..        .:       .:    .:    .:::..    :.    ..  
      :=+++=---=+#@@@###*++*##-   .-.  .:-.     .-:-      .-  .::    .-.  ..    -:    ::  
          .**---=%##%#****#*:     .-.    .-    .-. ::     .-.:-.      :::..     -:::::-:  
           %=--*#====##***#:      .-.    :-    --:::-:    .-:.:-.        .:-.   -:    ::  
          *+--#*==+==-+%**=#.     .-:.::::    -:     ::   .-    ::   .::..::    -:    ::  
         .%-:#*-*+:=**=-%#*-#:                                                            
         -#-=#-*=    :**:*%*:#:    :.:..:.. :  :.:.:.. .:.....:.:. ..: :..: : ..:...:...  
         =#.%--*       -#=-%#.%    ........ .  . . . . ... . .. .. ... .  . . . ........  
         -*=*:%          -*=*##:                                                          
          %#-#.            .--                                                            
          .++.                                                                                                                                              
               '''
    banner = '''
=============================================================
Daksh SCRA (Source Code Review Assist)

Author:     Debasis Mohanty
            www.coffeeandsecurity.com
            Twitter: @coffensecurity
            Email: d3basis.m0hanty@gmail.com
=============================================================
'''
    # Get the width of the terminal window
    _, columns = os.popen('stty size', 'r').read().split()

    # Calculate the padding based on the terminal width
    padding = int(columns) - len(starfish.split('\n')[1]) - 2

    # Print the banner with starfish and centered text
    print(starfish.center(int(columns)))
    print(banner.center(int(columns)))
    print(''.center(int(columns), '-'))
