"""nixfisical -- declarative management of a self-hosted Infisical instance.

This package is a direct port of an Ansible role that did two things: it
bootstrapped a freshly deployed Infisical container (superadmin, organization,
machine identity) and it pushed secrets read out of SOPS into that instance.
The role worked, but it lived inside a playbook run and inherited two
limitations we deliberately fix here:

* It assumed a single global SOPS secrets file. Real estates keep secrets in
  several files (per service, per host, per trust boundary), so the manifest
  carries a per-entry ``sopsFile``.
* It treated "the admin credentials file exists" as proof that bootstrap had
  succeeded. We instead prove it by logging in with the recorded machine
  identity, and refuse to re-bootstrap over a file we cannot authenticate with.

The public surface is the ``nixfisical`` console script; see ``cli``.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
