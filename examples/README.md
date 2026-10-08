# Insecure scanner fixture

`insecure/sample.py` contains deliberately vulnerable patterns and an unmistakably fake credential.
SecRAGraph reads this file as text for tests and demonstrations; it must never import or execute it.
Do not replace the demo value with a working credential.
