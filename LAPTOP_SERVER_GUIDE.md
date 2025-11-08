# 💻 Using Your Laptop as Pager-proper Server

## Quick Start Guide

### 🚀 **Step 1: Start the Server**
```bash
./start_laptop_server.sh
```
Choose option:
- **Option 1**: Only this laptop can connect (testing)
- **Option 2**: Other devices on your WiFi can connect 
- **Option 3**: Maximum compatibility (recommended)

### 📱 **Step 2: Start Client(s)**
```bash
./start_client.sh
```
Choose connection type and enter username/safetoken.

## 🌐 **Connection Scenarios**

### **Scenario A: Testing on Same Laptop**
1. **Terminal 1**: `./start_laptop_server.sh` → Choose option 1
2. **Terminal 2**: `./start_client.sh` → Choose option 1 (localhost)
3. **Terminal 3**: `./start_client.sh` → Choose option 1 (localhost)
4. Now you can message between the two clients!

### **Scenario B: Local Network (WiFi)**
1. **Laptop**: `./start_laptop_server.sh` → Choose option 2 or 3
2. **Same laptop**: `./start_client.sh` → Choose option 1 (127.0.0.1)
3. **Phone/Other laptop**: Connect to `10.110.23.179:5050`
4. **Friend's laptop**: Connect to `10.110.23.179:5050`

### **Scenario C: Internet Access (Advanced)**
Your laptop as internet server (requires router configuration):
1. **Router setup**: Port forward 5050 → your laptop IP
2. **Laptop**: `./start_laptop_server.sh` → Choose option 3
3. **Anyone on internet**: Connect to `[your-public-ip]:5050`

## 📋 **What You Get**

✅ **True End-to-End Encryption**: Each user has unique RSA keys  
✅ **Cross-Platform**: Works on Mac, Linux, Windows  
✅ **Local Network**: Friends on same WiFi can join  
✅ **Offline Messages**: Messages delivered when users return  
✅ **User Discovery**: See who's online  
✅ **Message Authentication**: Verify sender identity  

## 🔧 **Manual Usage**

### Start Server Manually:
```bash
/Users/macbook/Pager-proper/.venv/bin/python server.py
```

### Start Client Manually:
```bash
/Users/macbook/Pager-proper/.venv/bin/python client.py
# Enter server IP when prompted
```

## 📱 **Client Commands**
- Type username to send message
- `users` - List online and registered users  
- `quit` - Exit application

## 🔍 **Troubleshooting**

### **"Connection refused"**
- Make sure server is running
- Check IP address is correct
- Try localhost (127.0.0.1) first

### **"Port already in use"**
- Stop existing server: `pkill -f "python.*server.py"`
- Or use different port in server.py

### **"Can't reach from other devices"**
- Check firewall settings on laptop
- Make sure server uses 0.0.0.0, not 127.0.0.1
- Verify other devices are on same WiFi network

### **"Import errors"**
- Make sure dependencies installed: `pip install pycryptodome`
- Use the full python path: `/Users/macbook/Pager-proper/.venv/bin/python`

## 🌍 **Making It Internet Accessible**

### **Option 1: Dynamic DNS + Port Forwarding**
1. Set up dynamic DNS (DuckDNS, No-IP)
2. Configure router to forward port 5050 to laptop
3. Give friends your domain: `yourname.duckdns.org:5050`

### **Option 2: VPN Setup**
1. Set up VPN server (Tailscale, WireGuard)
2. Friends connect to VPN
3. Use laptop's VPN IP address

### **Option 3: Cloud Deployment**
1. Get a cheap VPS ($5/month)
2. Upload files and run `./deploy.sh`
3. Much more reliable than laptop

## 💡 **Pro Tips**

- **Keep laptop plugged in** when acting as server
- **Use WiFi + Ethernet** for better stability  
- **Test locally first** before trying network access
- **Save connection details** for friends to reuse
- **Monitor with**: `tail -f user_keys.json` (see registrations)

## 🔒 **Security Notes**

- Each user gets unique encryption keys
- Server never sees message content
- Private keys stored on each device
- Safetokens act as passwords
- Messages signed for authenticity

Your laptop is now a secure messaging server! 🎉