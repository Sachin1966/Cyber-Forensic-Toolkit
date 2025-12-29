import shutil
import os

BASE_DIR = os.getcwd() # Should be forensic-ai-hub root
DIST_DIR = os.path.join(BASE_DIR, 'dist')
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')
TEMPLATES_DIR = os.path.join(BACKEND_DIR, 'templates')
STATIC_DIR = os.path.join(BACKEND_DIR, 'static')

print(f"Deploying from {DIST_DIR} to {BACKEND_DIR}")

# 1. Copy index.html
if not os.path.exists(TEMPLATES_DIR):
    os.makedirs(TEMPLATES_DIR)
# index.html might be in dist or dist/index.html depending on how vite builds
# But usually dist/index.html
shutil.copy(os.path.join(DIST_DIR, 'index.html'), os.path.join(TEMPLATES_DIR, 'index.html'))
print("✅ Copied index.html to templates")

# 2. Copy assets
ASSETS_SRC = os.path.join(DIST_DIR, 'assets')
ASSETS_DEST = os.path.join(STATIC_DIR, 'assets')

if os.path.exists(ASSETS_SRC):
    if os.path.exists(ASSETS_DEST):
        # We need to be careful not to delete other static files if any, but usually assets is safe to replace
        shutil.rmtree(ASSETS_DEST) 
    shutil.copytree(ASSETS_SRC, ASSETS_DEST)
    print("✅ Copied assets to static/assets")
else:
    print("⚠️ No assets folder found in dist!")

print("Deployment Complete.")
