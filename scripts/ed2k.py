"""Run the ed2k-client command line from a checkout, through the project environment.

Usage from ``PoCs/ed2k-client``::

    uv run scripts/ed2k.py search "springer 2025" --json
    uv run scripts/ed2k.py --config config.example.toml download "ed2k://|file|Book.pdf|5648714|E737E3459E12C22118C48306FAE1D8EB|/"

``uv run`` installs the package into the project environment first, so this launcher only hands the arguments to
:func:`ed2k_client.cli.main`, the same entry point as the ``ed2k-client`` command and ``python -m ed2k_client``.
"""

import sys

from ed2k_client.cli import main

sys.exit(main())
