#!/usr/bin/env python3
"""
Database URL Debug Script
This script helps debug database URL connection issues.
"""

import os
import sys
import logging
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Debug the database URL"""
    print("🔍 Debugging Database URL")
    print("=" * 50)
    
    # Show all environment variables related to database
    print("Database-related environment variables:")
    db_vars = {k: v for k, v in os.environ.items() if "DATABASE" in k.upper() or "DB_" in k.upper()}
    
    if not db_vars:
        print("  No database-related environment variables found")
        return 1
    
    for key, value in db_vars.items():
        if "PASSWORD" in key.upper() or "SECRET" in key.upper():
            print(f"  {key}: ***")
        else:
            print(f"  {key}: {value}")
    
    print("\n" + "=" * 50)
    
    # Check DATABASE_URL specifically
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("❌ DATABASE_URL environment variable not set")
        return 1
    
    print(f"DATABASE_URL: {database_url}")
    
    # Parse the URL
    try:
        parsed = urlparse(database_url)
        print(f"Parsed URL:")
        print(f"  Scheme: {parsed.scheme}")
        print(f"  Hostname: {parsed.hostname}")
        print(f"  Port: {parsed.port}")
        print(f"  Path: {parsed.path}")
        
        if not parsed.hostname:
            print("❌ No hostname found in DATABASE_URL")
            return 1
            
        # Try to resolve the hostname
        import socket
        try:
            addr_info = socket.getaddrinfo(parsed.hostname, None)
            print(f"✅ Hostname resolves to: {[info[4][0] for info in addr_info]}")
        except socket.gaierror as e:
            print(f"❌ Hostname resolution failed: {e}")
            return 1
            
    except Exception as e:
        print(f"❌ Error parsing DATABASE_URL: {e}")
        return 1
    
    print("\n✅ Database URL appears to be valid")
    return 0

if __name__ == "__main__":
    sys.exit(main())