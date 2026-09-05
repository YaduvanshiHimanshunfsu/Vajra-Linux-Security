# Test lab

Run all scenarios only in an isolated Linux VM or disposable container environment.
No test creates persistence or performs real external exfiltration.

Initial scenarios to automate:

1. A normal web-service process chain.
2. Execution from `/tmp` using a benign test binary.
3. Synthetic sensitive-file access event.
4. A first-seen outbound destination represented by a local test endpoint.
5. Memory/IO pressure through bounded stress tooling.
