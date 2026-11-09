"""rhcl-probe exercises a Connectivity Link API gateway and an OpenShift Service Mesh with a
small demo app and reports which features work. One image, one role per Deployment:

    python -m rhcl_probe                    serve the role in $ROLE (frontend, catalog, pricing,
                                            outsider, console)
    python -m rhcl_probe check --url URL    run the suite on a console, exit 1 if anything failed
"""

import os

# Set by the image build (ARG VERSION); "dev" when run from a checkout.
__version__ = os.environ.get("RHCL_PROBE_VERSION", "dev")
