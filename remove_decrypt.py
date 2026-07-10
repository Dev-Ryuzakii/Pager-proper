import sys

file_path = "fastapi_mobile_backend_postgresql.py"
with open(file_path, "r") as f:
    lines = f.readlines()

new_lines = []
skip_mode = None

for i, line in enumerate(lines):
    if line.startswith("class DecryptService:"):
        skip_mode = "decrypt_service"
        continue
    
    if line.startswith("@app.post(\"/decrypt\")"):
        skip_mode = "decrypt_endpoint"
        continue
        
    if skip_mode == "decrypt_service":
        if line.startswith("class ") or line.startswith("def ") or line.startswith("@app."):
            if not line.startswith("    "): # Only stop if it's a top-level block
                skip_mode = None
                
    if skip_mode == "decrypt_endpoint":
        if line.startswith("@app.") and not line.startswith("@app.post(\"/decrypt\")"):
            skip_mode = None
            
    if skip_mode is None:
        new_lines.append(line)

with open(file_path, "w") as f:
    f.writelines(new_lines)
    
print("Successfully removed DecryptService and /decrypt endpoint.")
