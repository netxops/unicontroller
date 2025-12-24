.PHONY: build-agent package-agent upload-agent-to-platform release-agent
.PHONY: test-platform-connection

# Common variables
GIT_COMMIT := $(shell git rev-parse HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d %H:%M:%S')
VERSION := $(shell git describe --tags --always --dirty)
GIT_USER := $(shell git config user.name || echo "unknown")

# Agent variables
AGENT_VERSION := ${VERSION}
PLATFORM_API_URL ?= http://localhost:8080
PLATFORM_USERNAME ?= 
PLATFORM_ACCOUNT ?= ${PLATFORM_USERNAME}
PLATFORM_PASSWORD ?= 
AGENT_ZIP_FILE := agent-${AGENT_VERSION}.zip

# System information detection for Agent
# OS detection: uname -s (linux/darwin/windows)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  DETECTED_OS := linux
else ifeq ($(UNAME_S),Darwin)
  DETECTED_OS := darwin
else ifeq ($(UNAME_S),MINGW32_NT-6.1)
  DETECTED_OS := windows
else ifeq ($(UNAME_S),MINGW64_NT-6.1)
  DETECTED_OS := windows
else
  DETECTED_OS := linux
endif

# Architecture detection: uname -m with normalization
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  DETECTED_ARCH := amd64
else ifeq ($(UNAME_M),aarch64)
  DETECTED_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
  DETECTED_ARCH := arm64
else ifeq ($(UNAME_M),i386)
  DETECTED_ARCH := x86
else ifeq ($(UNAME_M),i686)
  DETECTED_ARCH := x86
else
  DETECTED_ARCH := $(UNAME_M)
endif

# Kernel version detection: uname -r, extract major.minor
UNAME_R := $(shell uname -r)
# Extract major.minor from kernel version (e.g., "5.10.0-123-generic" -> "5.10")
# Use sed with extended regex (works on both Linux and macOS)
DETECTED_KERNEL_VERSION := $(shell echo "$(UNAME_R)" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/' 2>/dev/null || echo "$(UNAME_R)" | sed 's/^\([0-9]\+\.[0-9]\+\).*/\1/')

# Allow manual override
AGENT_OS ?= ${DETECTED_OS}
AGENT_ARCH ?= ${DETECTED_ARCH}
AGENT_KERNEL_VERSION ?= ${DETECTED_KERNEL_VERSION}

# Agent targets
build-agent:
	@echo "Building Agent..."
	@echo "Version: ${AGENT_VERSION}"
	@echo "Git Commit: ${GIT_COMMIT}"
	@echo "Build Time: ${BUILD_TIME}"
	@mkdir -p build
	@echo "Executing: go build -ldflags \"-X github.com/influxdata/telegraf/controller/version.GitCommit=${GIT_COMMIT} -X 'github.com/influxdata/telegraf/controller/version.BuildTime=${BUILD_TIME}'\" -o build/agent ./agentv2/cmd/agentv2"
	@go build -v -ldflags "-X github.com/influxdata/telegraf/controller/version.GitCommit=${GIT_COMMIT} -X 'github.com/influxdata/telegraf/controller/version.BuildTime=${BUILD_TIME}'" -o build/agent ./agentv2/cmd/agentv2
	@echo "Agent built successfully: build/agent"

package-agent: build-agent
	@echo "Packaging Agent..."
	@echo "Detected OS: ${AGENT_OS}"
	@echo "Detected Architecture: ${AGENT_ARCH}"
	@echo "Detected Kernel Version: ${AGENT_KERNEL_VERSION}"
	@echo "Creating ZIP file: ${AGENT_ZIP_FILE}"
	@# 创建临时目录并复制文件，最后将 ZIP 文件移动到当前目录
	@mkdir -p /tmp/agent-package-$$$$ && \
		cp build/agent /tmp/agent-package-$$$$/agent && \
		cp deploy/package.json /tmp/agent-package-$$$$/package.json && \
		cp deploy/agent.yaml.template /tmp/agent-package-$$$$/agent.yaml.template && \
		cp deploy/agent.service.template /tmp/agent-package-$$$$/agent.service.template && \
		cd /tmp/agent-package-$$$$ && \
		zip -j ${AGENT_ZIP_FILE} agent package.json agent.yaml.template agent.service.template && \
		mv ${AGENT_ZIP_FILE} $(shell pwd)/ && \
		rm -rf /tmp/agent-package-$$$$
	@echo "ZIP file created: ${AGENT_ZIP_FILE}"

upload-agent-to-platform: package-agent
	@echo "Uploading Agent to platform..."
	@if [ -z "${PLATFORM_ACCOUNT}" ] && [ -z "${PLATFORM_USERNAME}" ]; then \
		echo "=========================================="; \
		echo "Error: Missing required environment variables"; \
		echo "=========================================="; \
		echo "Please set the following environment variables:"; \
		echo "  export PLATFORM_API_URL=http://127.0.0.1:8080"; \
		echo "  export PLATFORM_ACCOUNT=your-account (or PLATFORM_USERNAME)"; \
		echo "  export PLATFORM_PASSWORD=your-password"; \
		echo "=========================================="; \
		echo "Current values:"; \
		echo "  PLATFORM_API_URL: $${PLATFORM_API_URL:-not set}"; \
		echo "  PLATFORM_ACCOUNT: $${PLATFORM_ACCOUNT:-not set}"; \
		echo "  PLATFORM_USERNAME: $${PLATFORM_USERNAME:-not set}"; \
		echo "  PLATFORM_PASSWORD: $${PLATFORM_PASSWORD:-not set}"; \
		echo "=========================================="; \
		exit 1; \
	fi; \
	if [ -z "${PLATFORM_PASSWORD}" ]; then \
		echo "=========================================="; \
		echo "Error: PLATFORM_PASSWORD is required"; \
		echo "=========================================="; \
		exit 1; \
	fi
	@echo "Platform API URL: ${PLATFORM_API_URL}"
	@echo "Logging in to platform..."
	@login_response=$$(curl -s --max-time 10 --connect-timeout 5 -w "\n%{http_code}" -X POST \
		"${PLATFORM_API_URL}/api/v1/access/login" \
		-H "Content-Type: application/json" \
		-H "X-Auth-Token: placeholder" \
		-d "{\"login_type\":0,\"account\":\"${PLATFORM_ACCOUNT}\",\"password\":\"${PLATFORM_PASSWORD}\"}" 2>&1); \
	login_http_code=$$(echo "$$login_response" | tail -n1); \
	login_body=$$(echo "$$login_response" | sed '$$d'); \
	if [ -z "$$login_http_code" ] || [ "$$login_http_code" -lt 200 ] || [ "$$login_http_code" -ge 300 ] 2>/dev/null; then \
		echo "=========================================="; \
		echo "Login failed (HTTP $$login_http_code)"; \
		echo "=========================================="; \
		echo "API URL: ${PLATFORM_API_URL}/api/v1/access/login"; \
		echo "Account: ${PLATFORM_ACCOUNT}"; \
		if [ -n "$$login_body" ]; then \
			echo "Response body: $$login_body"; \
		else \
			echo "No response body received"; \
		fi; \
		echo "=========================================="; \
		echo "Troubleshooting tips:"; \
		echo "1. Check if the platform service is running"; \
		echo "2. Verify PLATFORM_API_URL is correct"; \
		echo "3. Check network connectivity"; \
		echo "4. Verify username and password are correct"; \
		echo "=========================================="; \
		exit 1; \
	fi; \
	login_code=$$(echo "$$login_body" | sed -n 's/.*"code"[[:space:]]*:[[:space:]]*\([0-9-]*\).*/\1/p' | head -n1); \
	if [ -n "$$login_code" ] && [ "$$login_code" != "0" ] 2>/dev/null; then \
		login_msg=$$(echo "$$login_body" | sed -n 's/.*"msg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1); \
		echo "=========================================="; \
		echo "Login failed"; \
		echo "=========================================="; \
		echo "Error code: $$login_code"; \
		if [ -n "$$login_msg" ]; then echo "Error message: $$login_msg"; fi; \
		echo "Response: $$login_body"; \
		echo "=========================================="; \
		echo "Please check:"; \
		echo "1. PLATFORM_ACCOUNT (or PLATFORM_USERNAME) is correct"; \
		echo "2. PLATFORM_PASSWORD is correct"; \
		echo "3. User account exists and is active"; \
		echo "=========================================="; \
		exit 1; \
	fi; \
	platform_token=$$(echo "$$login_body" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1); \
	if [ -z "$$platform_token" ]; then \
		echo "=========================================="; \
		echo "Error: Failed to extract token from login response"; \
		echo "=========================================="; \
		echo "Response: $$login_body"; \
		echo "=========================================="; \
		echo "The login request may have succeeded but the response format is unexpected."; \
		echo "Please check the API response format."; \
		echo "=========================================="; \
		exit 1; \
	fi; \
	echo "Login successful, token obtained"; \
	echo "Version: ${AGENT_VERSION}"; \
	echo "OS: ${AGENT_OS}"; \
	echo "Architecture: ${AGENT_ARCH}"; \
	echo "Kernel Version: ${AGENT_KERNEL_VERSION}"; \
	if [ ! -f "${AGENT_ZIP_FILE}" ]; then \
		echo "=========================================="; \
		echo "Error: ZIP file not found: ${AGENT_ZIP_FILE}"; \
		echo "=========================================="; \
		echo "Please run 'make package-agent' first to create the ZIP file."; \
		echo "Current directory: $$(pwd)"; \
		echo "Looking for: ${AGENT_ZIP_FILE}"; \
		echo "=========================================="; \
		exit 1; \
	fi; \
	zip_file_size=$$(stat -f%z "${AGENT_ZIP_FILE}" 2>/dev/null || stat -c%s "${AGENT_ZIP_FILE}" 2>/dev/null || echo "unknown"); \
	echo "ZIP file: ${AGENT_ZIP_FILE} (size: $$zip_file_size bytes)"; \
	echo "Uploading ${AGENT_ZIP_FILE}..."; \
	upload_response=$$(curl -v --max-time 300 --connect-timeout 30 -w "\n%{http_code}" -X POST \
		"${PLATFORM_API_URL}/api/v1/platform/agent-packages/upload" \
		-H "X-Auth-Token: $$platform_token" \
		-F "version=${AGENT_VERSION}" \
		-F "os=${AGENT_OS}" \
		-F "architecture=${AGENT_ARCH}" \
		-F "kernelVersion=${AGENT_KERNEL_VERSION}" \
		-F "file=@${AGENT_ZIP_FILE}" \
		-F "description=Agent build from Makefile" \
		-F "uploader=${GIT_USER}" 2>&1); \
	upload_http_code=$$(echo "$$upload_response" | tail -n1); \
	upload_body=$$(echo "$$upload_response" | sed '$$d'); \
	if [ "$$upload_http_code" = "000" ]; then \
		echo "=========================================="; \
		echo "Upload failed: Connection error (HTTP 000)"; \
		echo "=========================================="; \
		echo "Possible causes:"; \
		echo "1. Platform service is not running or not accessible"; \
		echo "2. Network connectivity issue"; \
		echo "3. Firewall blocking the connection"; \
		echo "4. File too large or upload timeout"; \
		echo "5. Incorrect PLATFORM_API_URL: ${PLATFORM_API_URL}"; \
		echo "=========================================="; \
		echo "Full curl response:"; \
		echo "$$upload_response"; \
		echo "=========================================="; \
		exit 1; \
	elif [ -n "$$upload_http_code" ] && [ "$$upload_http_code" -ge 200 ] && [ "$$upload_http_code" -lt 300 ] 2>/dev/null; then \
		echo "Upload successful (HTTP $$upload_http_code)"; \
		if [ -n "$$upload_body" ]; then echo "Response: $$upload_body"; fi; \
	else \
		echo "=========================================="; \
		echo "Upload failed (HTTP $$upload_http_code)"; \
		echo "=========================================="; \
		if [ -n "$$upload_body" ]; then \
			echo "Response body: $$upload_body"; \
		else \
			echo "No response body received"; \
		fi; \
		echo "=========================================="; \
		exit 1; \
	fi
	@echo "Upload complete."

test-platform-connection:
	@echo "Testing platform connection..."
	@if [ -z "${PLATFORM_API_URL}" ]; then \
		echo "Error: PLATFORM_API_URL environment variable is required"; \
		exit 1; \
	fi
	@echo "Platform API URL: ${PLATFORM_API_URL}"
	@echo "Testing connectivity..."
	@echo "Trying health check endpoint..."
	@test_response=$$(curl -s --max-time 10 --connect-timeout 5 -w "\n%{http_code}" -X GET "${PLATFORM_API_URL}/api/v1/sys/health" 2>&1 || echo "Connection failed\n000"); \
	test_http_code=$$(echo "$$test_response" | tail -n1); \
	test_body=$$(echo "$$test_response" | sed '$$d' 2>/dev/null || echo ""); \
	if [ "$$test_http_code" = "000" ] || [ -z "$$test_http_code" ] || [ "$$test_http_code" -lt 200 ] || [ "$$test_http_code" -ge 400 ] 2>/dev/null; then \
		echo "Health check endpoint not available (HTTP $$test_http_code), trying login endpoint instead..."; \
		if [ -z "${PLATFORM_ACCOUNT}" ] && [ -z "${PLATFORM_USERNAME}" ]; then \
			echo "Warning: Cannot test login endpoint without credentials"; \
			echo "Platform may be running, but cannot verify without PLATFORM_ACCOUNT (or PLATFORM_USERNAME) and PLATFORM_PASSWORD"; \
		else \
			login_test_response=$$(curl -s --max-time 10 --connect-timeout 5 -w "\n%{http_code}" -X POST \
				"${PLATFORM_API_URL}/api/v1/access/login" \
				-H "Content-Type: application/json" \
				-H "X-Auth-Token: placeholder" \
				-d "{\"login_type\":0,\"account\":\"${PLATFORM_ACCOUNT}\",\"password\":\"invalid_test_password\"}" 2>&1 || echo "Connection failed\n000"); \
			login_test_code=$$(echo "$$login_test_response" | tail -n1); \
			if [ "$$login_test_code" = "000" ]; then \
				echo "=========================================="; \
				echo "Connection test failed"; \
				echo "=========================================="; \
				echo "Unable to connect to ${PLATFORM_API_URL}"; \
				echo "Possible issues:"; \
				echo "1. Platform service is not running"; \
				echo "2. Incorrect PLATFORM_API_URL"; \
				echo "3. Network connectivity problem"; \
				echo "4. Firewall blocking the connection"; \
				echo "=========================================="; \
				exit 1; \
			elif [ "$$login_test_code" -ge 200 ] && [ "$$login_test_code" -lt 500 ] 2>/dev/null; then \
				echo "Login endpoint accessible (HTTP $$login_test_code), platform is running"; \
				test_http_code=$$login_test_code; \
			else \
				echo "=========================================="; \
				echo "Connection test failed (HTTP $$login_test_code)"; \
				echo "=========================================="; \
				echo "Unable to connect to ${PLATFORM_API_URL}"; \
				echo "=========================================="; \
				exit 1; \
			fi; \
		fi; \
	elif [ -z "$$test_http_code" ] || [ "$$test_http_code" -lt 200 ] || [ "$$test_http_code" -ge 300 ] 2>/dev/null; then \
		echo "=========================================="; \
		echo "Connection test failed (HTTP $$test_http_code)"; \
		echo "=========================================="; \
		echo "Server responded but with an error status"; \
		if [ "$$test_http_code" = "502" ]; then \
			echo "HTTP 502 Bad Gateway - Possible causes:"; \
			echo "  - Upstream server is not responding"; \
			echo "  - Reverse proxy/gateway configuration issue"; \
			echo "  - Service is down or not properly started"; \
		elif [ "$$test_http_code" = "503" ]; then \
			echo "HTTP 503 Service Unavailable - Service may be temporarily down"; \
		elif [ "$$test_http_code" = "404" ]; then \
			echo "HTTP 404 Not Found - Endpoint may not exist"; \
		fi; \
		if [ -n "$$test_body" ]; then echo "Response: $$test_body"; fi; \
		echo "=========================================="; \
		exit 1; \
	else \
		echo "Connection successful (HTTP $$test_http_code)"; \
		if [ -n "$$test_body" ]; then echo "Response: $$test_body"; fi; \
	fi
	@echo "Testing login endpoint..."
	@if [ -z "${PLATFORM_ACCOUNT}" ] && [ -z "${PLATFORM_USERNAME}" ]; then \
		echo "Warning: PLATFORM_ACCOUNT (or PLATFORM_USERNAME) not set, skipping login test"; \
	elif [ -z "${PLATFORM_PASSWORD}" ]; then \
		echo "Warning: PLATFORM_PASSWORD not set, skipping login test"; \
	else \
		login_test=$$(curl -s --max-time 10 --connect-timeout 5 -w "\n%{http_code}" -X POST \
			"${PLATFORM_API_URL}/api/v1/access/login" \
			-H "Content-Type: application/json" \
			-H "X-Auth-Token: placeholder" \
			-d "{\"login_type\":0,\"account\":\"${PLATFORM_ACCOUNT}\",\"password\":\"${PLATFORM_PASSWORD}\"}" 2>&1); \
		login_test_code=$$(echo "$$login_test" | tail -n1); \
		login_test_body=$$(echo "$$login_test" | sed '$$d' 2>/dev/null || echo ""); \
		if [ "$$login_test_code" -ge 200 ] && [ "$$login_test_code" -lt 300 ] 2>/dev/null; then \
			echo "Login endpoint test successful (HTTP $$login_test_code)"; \
		else \
			echo "Login endpoint test failed (HTTP $$login_test_code)"; \
			if [ -n "$$login_test_body" ]; then echo "Response: $$login_test_body"; fi; \
		fi; \
	fi
	@echo "Connection test completed."

release-agent: upload-agent-to-platform
	@echo "=========================================="
	@echo "Agent Release ${AGENT_VERSION} completed"
	@echo "=========================================="
	@echo "Version: ${AGENT_VERSION}"
	@echo "OS: ${AGENT_OS}"
	@echo "Architecture: ${AGENT_ARCH}"
	@echo "Kernel Version: ${AGENT_KERNEL_VERSION}"
	@echo "ZIP file: ${AGENT_ZIP_FILE}"
	@echo "Platform API: ${PLATFORM_API_URL}"
	@echo "=========================================="

# Deployment Agent targets
deployment-agent-%:
	@make -f Makefile.deployment-agent $*

.PHONY: deployment-agent-%