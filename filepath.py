import os
import os.path


def get_files_path(path: str) -> str:
    """Traverses through all the sub directories in the path and yields the full path of files found"""
    if os.path.isdir(path):
        for dirpath, _, filenames in os.walk(path):  # Second received output argument (dirname) is irrelevant
            for filename in filenames:
                yield os.path.join(dirpath, filename)

