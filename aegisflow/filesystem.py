import os
import pathlib
from typing import List, Union

class ProtectedZones:
    """
    Guards specific directories and files from modification or deletion.
    """
    
    DEFAULT_PROTECTED_PATHS = [
        # OS Specific System Paths (Expanded logic needed for robust cross-platform)
        "C:\\Windows", 
        "C:\\Program Files",
        "/etc", 
        "/var",
        
        # Sensitive Files
        ".env", 
        "id_rsa", 
        "id_ed25519",
        
        # Self Protection
        "aegisflow", 
    ]

    def __init__(self, protected_paths: List[str] = None):
        self.protected_paths = [pathlib.Path(p).resolve() for p in (protected_paths or self.DEFAULT_PROTECTED_PATHS)]

    def is_safe(self, target_path: Union[str, pathlib.Path]) -> bool:
        """
        Checks if the target path matches or is inside a protected zone.
        Returns False if the operation should be blocked.
        """
        try:
            target = pathlib.Path(target_path).resolve()
        except OSError:
            # If path doesn't exist or is invalid, we might want to block or pass depending on strictness
            # For deletion, it usually implies the path exists. For creation, check parent.
            return True # Let OS handle invalid paths, we care about *existing* protected zones

        # Check if target is exactly a protected file
        if target in self.protected_paths:
            return False

        # Check if target is inside a protected directory
        for protected in self.protected_paths:
            # If protected path is a parent of target
            try:
                target.relative_to(protected)
                return False # It is inside!
            except ValueError:
                continue
                
        return True
