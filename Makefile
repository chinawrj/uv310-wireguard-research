.PHONY: test test-live test-observer stack-audit verify

test:
	python3 tools/test_offline.py rekey-memory

test-live:
	python3 tools/test_offline.py rekey-live

verify:
	python3 tools/verify_publication.py

test-observer:
	python3 work/uv310-wireguard/rekey-observe/test_observe.py

stack-audit:
	python3 tools/stack_audit.py
