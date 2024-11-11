import os, re
import chardet
import ruamel.yaml

from pathlib import Path    # Resolve the windows / mac / linux path issue

import state.runtime_state as runtime


# Current directory of the python file
parentPath = os.path.dirname(os.path.realpath(__file__))


def saveYaml(file_path, data):
    with open(file_path, "w") as file:
        ruamel.yaml.safe_dump(data, file)



def detectEncodingType(targetfile):
    # Open the file in binary mode and read the first 1000 bytes to detect the encoding type
    with open(targetfile, 'rb') as f:
        result = chardet.detect(f.read(1000))
        
    return result['encoding']


def readfile_FallbackEncoding(filepath, fallback_order=("ISO-8859-1", "utf-8")):
    """
    Opens a file with specified encodings in fallback order.

    Parameters:
        filepath (str): The path to the file to open.
        fallback_order (tuple): Encodings to try in order.

    Returns:
        file object: The file object opened with the first successful encoding.

    Raises:
        IOError: If all encodings fail.
    """
    for encoding in fallback_order:
        try:
            return open(filepath, 'r', encoding=encoding)
        except (UnicodeDecodeError, ValueError):
            continue
    raise IOError(f"Could not open file {filepath} with any of the specified encodings: {fallback_order}")




def getReportsRootPath(fpath):
    """
    Returns the relative path from the '/reports' directory in a given file path.

    Converts an absolute path to a relative path starting from '/reports' if it exists.
    If the path is already relative or '/reports' is not found, the full path or None is returned.

    Parameters:
        fpath (str or Path): The file path to convert.

    Returns:
        str or None: Relative path from '/reports' or None if '/reports' is not found.
    """

    # Convert PosixPath object to string
    fpath = str(fpath)

    # Check if the path is relative
    if not os.path.isabs(fpath):
        return fpath  # Return full path if it is relative

    # Get the index of the '/reports' directory in the full file path
    reports_index = fpath.find('/reports')

    # Check if '/reports' directory exists in the path
    if reports_index == -1:
        return None  # Return None if '/reports' directory is not found

    # Extract the relative path from the '/reports' directory onwards
    relative_path = fpath[reports_index:]

    return relative_path



# Retrieve files extention from file path
def getFileExtention(fpath):
    extention = Path(str(fpath)).suffix

    return extention



def dirCleanup(dirname):
    """
    Clears all files in the specified temporary directory. If the directory 
    does not exist, it creates it.

    Parameters:
        dirname (str): Name of the directory to clean up.

    Returns:
        None
    """

    dir_path = Path(parentPath) / ".." / dirname
    if dir_path.exists():
        for file in dir_path.iterdir():
            if file.is_file():
                try:
                    file.unlink()
                except Exception as e:
                    print(f"Error removing file {file}: {e}")
    else:
        dir_path.mkdir(parents=True)



def getSourceFilePath(project_dir, source_file):
    pattern = re.compile(project_dir + '.+')

    source_filepath = ''
    try:
        source_filepath = pattern.search(source_file)[0]
    except TypeError as e:      # The "'NoneType' object is not subscriptable" error occurs on windows. 
        source_filepath = source_file

    return source_filepath



def getShortPath(file_path):
    short_file_path = getSourceFilePath(runtime.sourcedir, file_path)

    directory, filename = os.path.split(file_path)
    # Check if the filename length including extension is greater than 20 characters
    if len(filename) > 40:
        base, ext = os.path.splitext(filename)
        filename = f"[FILENAME-TOO-LONG]{ext}"  # Updated name

    shortened = '..[SHORTENED]..'
    return f"{os.sep}{directory.split(os.sep)[1]}{os.sep}{shortened}{os.sep}{filename}"



def cleanFilePaths(filepaths_source):
    """
    Cleans file paths by replacing absolute paths with relative project paths.

    Parameters:
        filepaths_source (str): The source file path for which to clean paths.

    Returns:
        None: The function writes cleaned paths to a text file.
    """

    target_dir = os.path.dirname(filepaths_source)
    source_file = os.path.join(target_dir, "filepaths.log")
    dest_file = os.path.join(target_dir, "filepaths.txt")

    with open(source_file, "r") as h_sf, open(dest_file, "w") as h_df:
        for eachfilepath in h_sf:  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()  # strip out '\r' or '\n' from the file paths
            h_df.write(getSourceFilePath(runtime.sourcedir, filepath) + "\n")

    runtime.discovered_clean_Fpaths = dest_file
    #os.unlink(source_file)



