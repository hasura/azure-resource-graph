# Azure Resource Graph Client - Test Suite

This directory contains pytest-compatible tests for the Azure Resource Graph Client.

## Quick Start

```bash
# Install test dependencies
pip install -e .[dev]

# Run all tests
pytest

# Or use the test runner
python run_tests.py --all
```

## Test Categories

### Test Markers

- `@pytest.mark.auth` - Authentication tests
- `@pytest.mark.query` - Basic query tests  
- `@pytest.mark.storage` - Storage encryption tests
- `@pytest.mark.compliance` - Compliance reporting tests
- `@pytest.mark.slow` - Slow tests (>5 seconds)
- `@pytest.mark.integration` - Tests requiring Azure credentials
- `@pytest.mark.unit` - Unit tests (no external dependencies)

### Running Specific Test Categories

```bash
# Run only unit tests (fast, no Azure required)
pytest -m "unit"

# Run only integration tests (requires Azure credentials)
pytest -m "integration"

# Run authentication tests
pytest -m "auth"

# Run storage encryption tests
pytest -m "storage"

# Run compliance tests
pytest -m "compliance"

# Run fast tests (exclude slow ones)
pytest -m "not slow"
```

## Test Runner Options

Use the `run_tests.py` script for convenient test execution:

```bash
# Run all tests
python run_tests.py --all

# Run with coverage report
python run_tests.py --coverage

# Run only integration tests
python run_tests.py --integration

# Run only fast tests
python run_tests.py --fast

# Generate HTML test report
python run_tests.py --html-report

# List all available tests
python run_tests.py --list-tests

# Show pytest help
python run_tests.py --help-pytest
```

## Prerequisites

### For Unit Tests
- No Azure credentials required
- Tests mock data and basic functionality

### For Integration Tests
- Azure credentials configured (`.env` file or environment variables)
- Valid Azure subscription with resources
- Network connectivity to Azure

### Required Environment Variables
```bash
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_IDS=sub1,sub2  # optional
```

## Test Files

- `conftest.py` - Pytest configuration and fixtures
- `test_client.py` - Main test suite
- `__init__.py` - Test package initialization
- `README.md` - This file

## Test Structure

### Test Classes

- `TestClientInitialization` - Basic client setup
- `TestAuthentication` - Token retrieval and auth
- `TestBasicQueries` - Simple Resource Graph queries
- `TestStorageEncryption` - Storage encryption analysis
- `TestComplianceSummary` - Compliance reporting
- `TestApplicationSpecificQueries` - App-specific queries
- `TestErrorHandling` - Error scenarios
- `TestPerformance` - Performance validation
- `TestDataValidation` - Data structure validation
- `TestResultSaving` - Result persistence
- `TestFullWorkflow` - End-to-end workflows

### Fixtures

- `client` - Initialized Azure Resource Graph client
- `client_config` - Client configuration
- `access_token` - Valid Azure access token
- `storage_encryption_results` - Storage encryption query results
- `compliance_summary_results` - Compliance summary results
- `sample_basic_query` - Simple test query
- `invalid_query` - Invalid query for error testing
- `performance_timer` - Performance measurement utility

## Running Tests

### Basic Usage

```bash
# Run all tests with verbose output
pytest -v

# Run tests with coverage
pytest --cov=azure_resource_graph

# Run specific test file
pytest tests/test_client.py

# Run specific test class
pytest tests/test_client.py::TestAuthentication

# Run specific test method
pytest tests/test_client.py::TestAuthentication::test_token_retrieval
```

### Advanced Usage

```bash
# Run tests in parallel (requires pytest-xdist)
pytest -n auto

# Generate HTML coverage report
pytest --cov=azure_resource_graph --cov-report=html

# Generate JUnit XML for CI/CD
pytest --junit-xml=test_results.xml

# Stop on first failure
pytest -x

# Show test durations
pytest --durations=10

# Run only failed tests from last run
pytest --lf
```

## CI/CD Integration

For automated testing in CI/CD pipelines:

```bash
# Install dependencies
pip install -e .[dev]

# Run tests with XML output
pytest --junit-xml=test_results.xml --cov=azure_resource_graph --cov-report=xml

# Upload coverage to services like Codecov
# codecov -f coverage.xml
```

## Troubleshooting

### Common Issues

**"Azure credentials not configured"**
- Set up `.env` file or environment variables
- Verify credentials are valid
- Check network connectivity to Azure

**"Failed to initialize Azure client"**
- Check Azure credentials format
- Verify service principal permissions
- Check subscription access

**"No resources found"**
- This is often expected in test environments
- Tests are designed to handle empty results gracefully

**Tests are slow**
- Use `pytest -m "not slow"` for faster tests
- Check network connectivity
- Consider using parallel execution with `pytest -n auto`

### Debug Mode

```bash
# Run with extra debugging
pytest -vvv --tb=long

# Run single test with debugging
pytest -vvv --tb=long tests/test_client.py::TestAuthentication::test_token_retrieval

# Capture print statements
pytest -s
```

## Adding New Tests

When adding new tests:

1. Follow the naming convention: `test_*.py` files, `Test*` classes, `test_*` methods
2. Use appropriate markers (`@pytest.mark.integration`, etc.)
3. Add fixtures to `conftest.py` for reusable test data
4. Document test purpose and expected behavior
5. Handle both success and failure scenarios
6. Use meaningful assertions with descriptive error messages

## Test Data

Tests use both real Azure resources (integration tests) and mock data (unit tests):

- **Integration tests** query your actual Azure environment
- **Unit tests** use fixtures and mock data
- **Test results** are saved to temporary files and cleaned up automatically
