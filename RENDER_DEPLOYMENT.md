# Render Deployment Guide

This guide explains how to deploy the Secure Messaging API to Render.

## Prerequisites

1. A Render account (https://render.com)
2. A PostgreSQL database provisioned on Render

## Deployment Steps

### 1. Create a PostgreSQL Database on Render

1. Go to your Render Dashboard
2. Click "+ New" → "PostgreSQL"
3. Configure your database:
   - Choose a name (e.g., `secure-messaging-db`)
   - Select the same region as your web service
   - Choose an appropriate instance type
4. Click "Create Database"

### 2. Note the Database Connection Details

After your database is created:
1. Go to the database's "Info" page
2. Find the "External Database URL" in the "Connections" section
3. Copy this URL - you'll need it for the web service configuration

### 3. Create the Web Service

1. Go to your Render Dashboard
2. Click "+ New" → "Web Service"
3. Connect your Git repository
4. Configure the service:
   - Name: `secure-messaging-api`
   - Runtime: Python 3
   - Build Command: `pip install -r requirements_postgresql.txt`
   - Start Command: `./start_render.sh`
   - Plan: Choose an appropriate plan (Starter is fine for testing)

### 4. Configure Environment Variables

Add these environment variables to your web service:

```
DATABASE_URL=your_render_database_url_here
PORT=8000
```

Replace `your_render_database_url_here` with the actual database URL from step 2.

### 5. Deploy

Click "Create Web Service" and Render will automatically deploy your application.

## Health Checks

The application provides a `/health` endpoint that Render can use for health checks.

## Troubleshooting

### Database Connection Issues

If you see database connection errors:

1. Verify the DATABASE_URL environment variable is correctly set
2. Ensure your database and web service are in the same region
3. Check that your database is not suspended or paused

### Port Binding Issues

The application automatically uses the PORT environment variable provided by Render, so port binding issues should not occur.

### Startup Failures

If the application fails to start:

1. Check the logs in the Render Dashboard
2. Ensure all environment variables are correctly set
3. Verify the database is accessible

## Custom Domain (Optional)

To use a custom domain:

1. In your web service settings, go to "Custom Domains"
2. Add your domain
3. Follow Render's instructions for DNS configuration