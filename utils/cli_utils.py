def toolUsage(option):
    if option == 'invalid_dir':
        # Invalid directory usage examples
        print("\nExample commands for invalid directory error:")
        print("  python dakshsca.py -r php -t /path_to_source_dir")
        print("  python dakshsca.py -r php -f php -t /path_to_source_dir")
        print("  python dakshsca.py -r php,java,cpp -t /path_to_source_dir\n")
    else:
        # Tool usage examples
        print("\nUsage Examples:")

        # Platform-specific rule usage
        print("  # Specify platforms with '-r' (single or multiple) for platform-specific rules:")
        print("    - Single platform: dakshsca.py -r php -t /source_dir_path")
        print("    - Multiple platforms: dakshsca.py -r php,java,cpp -t /source_dir_path")
        print("    > Only the selected platform-specific rules will be applied to the corresponding project files.\n")

        # File types option
        print("  # '-f' is optional and defaults to the filetypes of the selected rule:")
        print("    - Example: dakshsca.py -r php -t /source_dir_path")
        print("  # To override the default, specify filetypes with '-f':")
        print("    - Example: dakshsca.py -r php -f dotnet -t /path_to_source_dir\n")

        # Reconnaissance
        print("  # Perform reconnaissance and rule-based scanning with '-recon' and '-r':")
        print("    - Example: dakshsca.py -recon -r php -t /path_to_source_dir")
        print("  # Perform reconnaissance only without '-r':")
        print("    - Example: dakshsca.py -recon -t /path_to_source_dir\n")

        # Verbosity
        print("  # Verbosity levels:")
        print("    - '-v' is default; '-vvv' displays all rule checks within each category.")
        print("    - Example: dakshsca.py -r php -vv -t /path_to_source_dir\n")

        # General Notes
        print("Note: Ensure to run the tool in the correct Python environment.")
        print("  Example: python3 dakshsca.py -r php -t /source_dir_path\n")
    
    return
