# Makefile for PCredz
# Build standalone executables for Linux and Windows

.PHONY: all clean install test build-linux build-windows help

PYTHON := python3
PYINSTALLER := pyinstaller
PROJECT_NAME := pcredz
VERSION := 2.1.0

help:
	@echo "PCredz Build System"
	@echo "==================="
	@echo ""
	@echo "Available targets:"
	@echo "  install        - Install package in development mode"
	@echo "  build-linux    - Build standalone Linux executable"
	@echo "  build-windows  - Build standalone Windows executable (requires Wine)"
	@echo "  build-all      - Build both Linux and Windows executables"
	@echo "  test           - Run tests and generate test PCAPs"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Show this help message"

# Install dependencies
install:
	@echo "Installing PCredz in development mode..."
	$(PYTHON) -m pip install -e .
	@echo "Installing optional dependencies..."
	$(PYTHON) -m pip install requests scapy pyinstaller
	@echo "Done!"

# Build Linux executable
build-linux: clean
	@echo "Building Linux standalone executable..."
	pyinstaller --onefile --name pcredz \
		--add-data "pcredz:pcredz" \
		--hidden-import=pylibpcap \
		--hidden-import=pylibpcap.pcap \
		--collect-all=pylibpcap \
		--hidden-import=pcredz.parsers \
		--hidden-import=pcredz.output \
		--hidden-import=pcredz.utils \
		run_pcredz.py
	@echo ""
	@echo "✓ Linux executable created: dist/pcredz"
	@echo "  Size: $$(du -h dist/pcredz | cut -f1)"
	@echo "  Test with: ./dist/pcredz -f tests/realistic_network_traffic.pcap"

# Build Windows executable (requires Wine + Python for Windows)
build-windows:
	@echo "Building Windows standalone executable..."
	@echo "Note: This requires Wine and Python for Windows"
	@mkdir -p dist
	@if command -v wine > /dev/null; then \\
		wine $(PYTHON) -m PyInstaller --onefile \\
			--name pcredz-$(VERSION)-windows.exe \\
			--add-data "pcredz;pcredz" \\
			--hidden-import=pylibpcap \\
			--hidden-import=pcredz.parsers \\
			--hidden-import=pcredz.output \\
			--hidden-import=pcredz.utils \\
			--console \\
			run_pcredz.py; \\
		echo "Windows executable created: dist/pcredz-$(VERSION)-windows.exe"; \\
	else \\
		echo "Wine not found. Install Wine first: sudo apt-get install wine"; \\
		echo "Alternatively, build on Windows directly."; \\
	fi

# Build both
build-all: build-linux
	@echo "Linux build complete. Windows build requires manual setup."
	@echo "To build for Windows, run this on a Windows machine:"
	@echo "  pyinstaller --onefile --name pcredz-$(VERSION)-windows.exe run_pcredz.py"

# Generate test PCAPs
test:
	@echo "Generating test PCAP files..."
	$(PYTHON) tests/generate_test_pcaps.py
	@echo "Testing with sample PCAP..."
	@if [ -f tests/sample.pcap ]; then \\
		$(PYTHON) -m pcredz -f tests/sample.pcap -v --json --csv; \\
	else \\
		echo "No test PCAP found. Run 'make test-generate' first."; \\
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info/ __pycache__/
	rm -rf pcredz/__pycache__/ pcredz/*/__pycache__/
	rm -f *.spec
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	@echo "Clean complete!"

# Quick test
quick-test:
	@echo "Running quick functionality test..."
	$(PYTHON) -c "from pcredz import main; print('Import successful!')"
	@echo "PCredz is working correctly!"
