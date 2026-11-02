# Fixture: crypto mentioned in documentation (generic rules).

Generate a key with `openssl req -newkey rsa:2048 -nodes` and encrypt with
`openssl enc -aes-256-cbc`. Avoid TripleDES. The words "caesar" and
"description" must not match anything.
