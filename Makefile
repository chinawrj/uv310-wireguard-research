.PHONY: test test-live verify

test:
	python3 tools/test_offline.py rekey-memory

test-live:
	python3 tools/test_offline.py rekey-live

verify:
	python3 tools/verify_publication.py
