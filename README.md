# log4j_checker_beta

This script is used to perform a fast check if your server is possibly affected by CVE-2021-44228 (the log4j vulnerability).
It does not give a 100% proof, that you are not vulnerable, but it gives a hint if it is possible, that you could be vulnerable.

- scans files for occurrences of log4j
- checks for packages containing log4j and Solr ElasticSearch
- checks if Java is installed
- Analyzes JAR/WAR/EAR files
- Option of checking hashes of .class files in archives

## Run with:

    wget https://raw.githubusercontent.com/pumburo/log4j_checker_beta/main/log4j_checker_beta.sh -q -O - | sudo bash

## Hash checking

The script can test .class files on the first level of JAR/WAR/EAR archives to see if they match with known sha256 hashes of vulnerable class files from log4j.
You have to provide a download of plain text file with sha256 hashes in HEX format, one per line, everything after first <space> is ignored.
The URL can be placed in variable download_file. Otherwise this feature will not operate.

