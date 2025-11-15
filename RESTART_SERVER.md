# Server Restart Required

The `/api/user-keys` endpoint has been added but requires a server restart to work.

## To Fix the 404 Error:

1. **Stop the current server** (if running):
   - Press `Ctrl+C` in the terminal where the server is running
   - Or close the terminal window

2. **Restart the server**:
   ```bash
   cd websocket
   node server.js
   ```

3. **Verify the server started**:
   - You should see: `Server running on port 10000`
   - You should see: `Loaded existing RSA keys` or `Generated new RSA key pair (2048 bits)`

4. **Refresh your browser** and try again

## If using nodemon (auto-restart):
```bash
cd websocket
npx nodemon server.js
```

This will automatically restart the server when files change.



