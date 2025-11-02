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

**Important**: The database needs to be created before deploying the web service, as the web service will try to connect to the database during startup.

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

### 4. Create the Background Worker for Message Cleanup

1. Go to your Render Dashboard
2. Click "+ New" → "Background Worker"
3. Connect your Git repository
4. Configure the service:
   - Name: `message-cleanup-worker`
   - Runtime: Python 3
   - Build Command: `pip install -r requirements_postgresql.txt`
   - Start Command: `python background_cleanup.py`
   - Plan: Choose an appropriate plan (Free is fine for the worker)

### 5. Configure Environment Variables

Add these environment variables to both your web service and background worker:

```
DATABASE_URL=your_render_database_url_here
PORT=8001
```

For the background worker, you can also add:

```
CLEANUP_INTERVAL_SECONDS=3600
```

Replace `your_render_database_url_here` with the actual database URL from step 2.

**Note**: Make sure to use the full DATABASE_URL from Render's dashboard, which should look something like:
`postgres://username:password@host:port/database_name`

### 6. Deploy

Click "Create Web Service" and "Create Background Worker" and Render will automatically deploy your application.

## Health Checks

The application provides a `/health` endpoint that Render can use for health checks.

## Disappearing Messages Feature

The application now includes support for disappearing messages that automatically delete after a specified time period. The background worker handles the automatic cleanup of expired messages.

## Troubleshooting

### Database Connection Issues

If you see database connection errors:

1. **Verify the DATABASE_URL environment variable is correctly set**
   - Check that it's not empty
   - Make sure it's the full URL from Render's dashboard
   - Ensure there are no extra spaces or characters

2. **Ensure your database and web service are in the same region**
   - This minimizes latency and enables communication over your private network

3. **Check that your database is not suspended or paused**
   - Go to your database's dashboard and verify its status

4. **Wait for the database to be fully ready**
   - Sometimes there's a delay between database creation and it being ready to accept connections

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