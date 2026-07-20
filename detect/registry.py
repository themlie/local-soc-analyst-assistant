"""
detect/registry.py — Registry for pluggable detectors.
"""

class DetectorRegistry:
    _detectors = []

    @classmethod
    def get_all(cls):
        """Return a list of all registered detector functions."""
        return cls._detectors

def register_detector(func):
    """Decorator to register a detector function."""
    DetectorRegistry._detectors.append(func)
    return func
