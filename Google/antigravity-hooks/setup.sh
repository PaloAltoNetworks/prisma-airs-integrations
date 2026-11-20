#!/bin/bash

# Setup script for Prisma AIRS Security Hooks — Google Antigravity
# Installs hooks to ~/.gemini/hooks/ and merges hooks.json into the
# appropriate Antigravity config directory.

set -e

HOOKS_DIR="${HOME}/.gemini/hooks"
CONFIG_DIR_GLOBAL="${HOME}/.gemini/config"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing Prisma AIRS hooks for Google Antigravity"

# Create hook install directory
mkdir -p "$HOOKS_DIR"

# Copy hook scripts
cp -r "${SCRIPT_DIR}/hooks/"*.sh "$HOOKS_DIR/"
chmod +x "${HOOKS_DIR}"/*.sh

echo "    ✅ Hook scripts installed to $HOOKS_DIR"

# Merge hooks.json into global config
mkdir -p "$CONFIG_DIR_GLOBAL"
HOOKS_TARGET="${CONFIG_DIR_GLOBAL}/hooks.json"

if [[ -f "$HOOKS_TARGET" ]]; then
    echo "    ⚠️  Existing hooks.json found at $HOOKS_TARGET"
    echo "    Merging (your existing hooks will be preserved)..."
    # Merge: combine top-level keys, new keys take precedence on conflict
    MERGED=$(jq -s '.[0] * .[1]' "$HOOKS_TARGET" "${SCRIPT_DIR}/hooks.json")
    echo "$MERGED" > "$HOOKS_TARGET"
else
    cp "${SCRIPT_DIR}/hooks.json" "$HOOKS_TARGET"
fi

echo "    ✅ hooks.json installed to $HOOKS_TARGET"
echo ""
echo "==> Next steps:"
echo ""
echo "    1. Add credentials to your shell profile (~/.bashrc or ~/.zshrc):"
echo "       export PRISMA_AIRS_API_KEY=\"your-api-key\""
echo "       export PRISMA_AIRS_PROFILE_NAME=\"your-profile-name\""
echo "       (see example.env for all options)"
echo ""
echo "    2. Reload your shell:"
echo "       source ~/.bashrc   # or ~/.zshrc"
echo ""
echo "    3. Test the installation:"
echo "       echo '{\"invocationNum\": 0, \"initialNumSteps\": 0, \"conversationId\": \"test\", \"workspacePaths\": [], \"transcriptPath\": \"\", \"artifactDirectoryPath\": \"\"}' | bash $HOOKS_DIR/scan-user-prompt.sh"
echo ""
echo "    4. Monitor the log:"
echo "       tail -f ~/.gemini/hooks/prisma-airs.log"
echo ""
echo "==> For workspace-scoped hooks (team policy):"
echo "    Copy hooks.json to .agents/hooks.json in your workspace."
echo "    Update command paths to use relative paths (e.g. ./.agents/hooks/)."
echo ""
echo "Done! Restart Antigravity for hooks to take effect."
