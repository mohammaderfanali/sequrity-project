"""Optional fuzzing extension.

Disabled by default. Generates inputs from a grammar and/or by mutating the
existing test corpus, executes them through the core pipeline's own sandboxed
runner, and triages the results with the core classifier.

Findings are reported separately from the authoritative verdict - see
:mod:`dynan.ext.fuzz.extension` for why, and for the promotion path that lets
a fuzz-discovered crash legitimately influence a later run.
"""
