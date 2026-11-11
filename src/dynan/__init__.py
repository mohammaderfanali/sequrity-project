"""dynAn - dynamic security patch validation for C/C++ ELF targets."""

__all__ = ["__version__", "PRODUCT_NAME", "RESULT_SCHEMA_VERSION"]

__version__ = "0.1.0"

#: Name shown in the CLI banner and the web UI.
PRODUCT_NAME = "dynAn"

#: Version of the ``results.json`` structure. Bump on any breaking change so
#: that stored runs remain interpretable by later releases.
RESULT_SCHEMA_VERSION = "1.0"
