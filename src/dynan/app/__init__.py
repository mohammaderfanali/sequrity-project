"""Application layer: use cases and orchestration.

Everything the CLI and the web UI can do is a service in this package. Neither
front end implements validation logic of its own; both call the same services
and render the same canonical models.
"""
