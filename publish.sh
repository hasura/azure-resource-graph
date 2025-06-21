#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

# Check if bump2version is installed
if ! command -v bump2version &> /dev/null; then
    print_error "❌ bump2version is not installed."
    echo "Install it with: pip install bump2version"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(python -c "import importlib.metadata; print(importlib.metadata.version('azure_resource_graph'))" 2>/dev/null || echo "unknown")

print_step "📦 Current version: $CURRENT_VERSION"
echo ""

# Ask user what type of version bump
echo "What type of version bump do you want?"
echo "1) patch (x.x.X) - Bug fixes"
echo "2) minor (x.X.x) - New features, backwards compatible"
echo "3) major (X.x.x) - Breaking changes"
echo "4) custom - Specify exact version"
echo "5) skip - Don't bump version"
echo ""

read -p "Enter choice (1-5): " choice

case $choice in
    1)
        BUMP_TYPE="patch"
        ;;
    2)
        BUMP_TYPE="minor"
        ;;
    3)
        BUMP_TYPE="major"
        ;;
    4)
        read -p "Enter new version (e.g., 1.2.3): " CUSTOM_VERSION
        BUMP_TYPE="--new-version $CUSTOM_VERSION patch"
        ;;
    5)
        print_warning "⏭️  Skipping version bump..."
        BUMP_TYPE=""
        ;;
    *)
        print_error "❌ Invalid choice. Exiting."
        exit 1
        ;;
esac

# Bump version if requested
if [ ! -z "$BUMP_TYPE" ]; then
    print_step "🔢 Bumping version ($BUMP_TYPE)..."
    bump2version $BUMP_TYPE

    # Get new version
    NEW_VERSION=$(python -c "import importlib.metadata; print(importlib.metadata.version('azure_resource_graph'))" 2>/dev/null || echo "unknown")
    print_success "✅ Version bumped: $CURRENT_VERSION → $NEW_VERSION"

    # Ask if user wants to commit and tag
    echo ""
    read -p "Do you want to commit and push the version bump? (y/N): " commit_choice
    if [[ $commit_choice =~ ^[Yy]$ ]]; then
        print_step "📝 Committing version bump..."
        git add .
        git commit -m "Bump version to $NEW_VERSION"
        git tag "v$NEW_VERSION"

        read -p "Push to remote? (y/N): " push_choice
        if [[ $push_choice =~ ^[Yy]$ ]]; then
            git push
            git push --tags
            print_success "✅ Pushed to remote"
        fi
    fi
fi

echo ""
print_step "🧹 Cleaning previous builds..."
rm -rf build dist *.egg-info

print_step "🏗️  Building package..."
python -m build

print_step "🔍 Checking package..."
twine check dist/*

# Ask before uploading to TestPyPI
echo ""
read -p "Upload to TestPyPI? (Y/n): " testpypi_choice
if [[ ! $testpypi_choice =~ ^[Nn]$ ]]; then
    print_step "🧪 Uploading to TestPyPI..."
    twine upload --repository testpypi dist/*

    print_success "✅ Uploaded to TestPyPI!"
    echo "🔗 Check: https://test.pypi.org/project/azure_resource_graph/"
else
    print_warning "⏭️  Skipped TestPyPI upload"
fi

echo ""
read -p "Upload to PyPI? (y/N): " pypi_choice
if [[ $pypi_choice =~ ^[Yy]$ ]]; then
    print_step "🚀 Uploading to PyPI..."
    twine upload dist/*
    print_success "✅ Uploaded to PyPI!"
    echo "🔗 Check: https://pypi.org/project/azure_resource_graph/"
else
    print_warning "⏭️  Skipped PyPI upload"
    echo ""
    echo "To upload to PyPI later, run:"
    echo "twine upload dist/*"
fi

print_success "🎉 Publish complete!"
