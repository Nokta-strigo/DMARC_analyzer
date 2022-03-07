# DMARC_analyzer
  Parse aggregated DMARC reports and show them in table (.csv).

  It takes an mbox file or a directory with .eml files as an input. For example you can create a "local folder" in Thunderbird and move all your DMARC reports to that folder. Then you can give path to mbox file <home folder>/.thunderbird/<thunderbird profile>/Mail/Local Folders/<folder name> to dmarc_analyser in -m parameter.
  
  Be aware that parsing untrusted data may pose a security risk. Although this program should not contain any known vulnerabilities, you may use some compensating measures, for example run it inside an isolated environment.
