.PHONY: audit-layout test-dhcp-growth test-dns-grow test-dns test-dhcp-dns test-pressure test test-live test-observer stack-audit verify

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

test-pressure:
	python3 tools/test_offline.py rekey-pressure

# Standalone prototype; no native device hook or firmware deployment.
test-dhcp-dns:
	python3 tools/test_dhcp_dns.py

# Native integration candidate; synthetic one-boot material only.
test-dns:
	python3 tools/test_offline.py rekey-dns

# Bounded DHCP buffer growth, synthetic only.
test-dhcp-growth:
	python3 tools/test_dhcp_growth.py

test-dns-grow:
	python3 tools/test_offline.py rekey-dns-grow

# Reports constraint violations; green audit execution does not mean all fit.
audit-layout:
	python3 tools/audit_native_layout.py --pool-bytes 1024 --out .test-results/native-layout-pool1024.json
	python3 tools/audit_native_layout.py --pool-bytes 1024 --lto --out .test-results/native-layout-pool1024-lto.json
	python3 tools/audit_native_layout.py --pool-bytes 256 --out .test-results/native-layout-pool256.json
	python3 tools/audit_native_layout.py --pool-bytes 256 --lto --out .test-results/native-layout-pool256-lto.json
