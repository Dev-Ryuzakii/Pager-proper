#!/bin/bash

# PostgreSQL Setup Script for Secure Messaging System
# This script helps install and configure PostgreSQL on macOS

echo "🐘 PostgreSQL Setup for Secure Messaging System"
echo "================================================"

# Check if PostgreSQL is already installed
if command -v psql &> /dev/null; then
    echo "✅ PostgreSQL is already installed"
    psql --version
else
    echo "📦 Installing PostgreSQL using Homebrew..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Please install Homebrew first:"
        echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    # Install PostgreSQL
    brew install postgresql@15
    
    # Start PostgreSQL service
    brew services start postgresql@15
    
    echo "✅ PostgreSQL installed and started"
fi

# Database configuration
DB_NAME="secure_messaging"
DB_USER="secure_user"
DB_PASSWORD="secure_password_2024"

echo ""
echo "🔧 Setting up database and user..."

# Create database and user
psql postgres -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || echo "Database may already exist"
psql postgres -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null || echo "User may already exist"
psql postgres -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" 2>/dev/null
psql postgres -c "ALTER USER $DB_USER CREATEDB;" 2>/dev/null

echo "✅ Database '$DB_NAME' and user '$DB_USER' configured"

# Create .env file for database connection
echo ""
echo "📝 Creating .env file with database configuration..."

cat > .env << EOF
# PostgreSQL Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME

# Application Settings
DEBUG=True
SECRET_KEY=your-secret-key-change-in-production-$(date +%s)
EOF

echo "✅ Created .env file with database settings"

# Test database connection
echo ""
echo "🧪 Testing database connection..."

python3 << EOF
import sys
import os
sys.path.append('.')

# Load environment variables
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

try:
    from database_config import init_database
    success = init_database()
    if success:
        print("✅ Database connection and setup successful!")
    else:
        print("❌ Database setup failed")
        sys.exit(1)
except Exception as e:
    print(f"❌ Error testing database: {e}")
    sys.exit(1)
EOF

echo ""
echo "🎉 PostgreSQL setup completed successfully!"
echo ""
echo "📋 Database Details:"
echo "   Host: localhost"
echo "   Port: 5432"
echo "   Database: $DB_NAME"
echo "   User: $DB_USER"
echo "   Password: $DB_PASSWORD"
echo ""
echo "🚀 Next steps:"
echo "   1. Run: python database_config.py (to test setup)"
echo "   2. Run: python migrate_to_postgresql.py (to migrate existing data)"
echo "   3. Update your applications to use PostgreSQL"
echo ""
echo "💡 Connection string saved in .env file"