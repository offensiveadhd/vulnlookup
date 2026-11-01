#!/usr/bin/env python3
"""vulnlookup: passive CVE / CPE / EPSS / KEV lookups. Python 3.10+, standard library only.

python vulnlookup.py cve CVE-2021-44228
python vulnlookup.py product "apache httpd" 2.4.49 --poc --recommend
python vulnlookup.py product openssl --years 2019-2024 --kev --format md
python vulnlookup.py resolve "log4j 2.14.1"
python vulnlookup.py --help
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vl.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
