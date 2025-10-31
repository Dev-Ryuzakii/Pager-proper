#!/usr/bin/env python3
"""
Environment Variable Checker
This script checks what environment variables are available.
"""

import os

def main():
    """Check environment variables"""
    print("🔍 Checking environment variables...")
    print("=" * 50)
    
    # Show all environment variables
    print("All environment variables:")
    for key, value in sorted(os.environ.items()):
        # Don't show sensitive information
        if "PASSWORD" in key.upper() or "SECRET" in key.upper() or "KEY" in key.upper():
            print(f"  {key}: ***")
        else:
            print(f"  {key}: {value}")
    
    print("\n" + "=" * 50)
    
    # Check specifically for database-related variables
    print("Database-related environment variables:")
    db_vars = [key for key in os.environ.keys() if "DATABASE" in key.upper() or "DB_" in key.upper()]
    if db_vars:
        for var in sorted(db_vars):
            value = os.environ.get(var, "Not set")
            if "PASSWORD" in var.upper() or "SECRET" in var.upper() or "KEY" in var.upper():
                print(f"  {var}: ***")
            else:
                print(f"  {var}: {value}")
    else:
        print("  No database-related environment variables found")

if __name__ == "__main__":
    main()