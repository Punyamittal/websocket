# SecureDrop - Secure File Transfer (Beginner Friendly)

This project implements a simple file transfer webapp where:
- Anyone can upload a file to a receiver by providing the receiver's username and 4-digit PIN.
- Uploaded files go into a **Pending** area; the receiver must **Accept** or **Reject** each pending file.
- When accepted, the file moves to **Approved** files and the receiver can download it.
- Storage: JSON (`/data/users.json`) + local file storage (`/uploads/pending` and `/uploads/approved`).

## Quick start

1. Extract the zip.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run:
   ```bash
   node server.js
   ```
4. Open `http://localhost:3000` in your browser.

## Notes for deployment on Render
- Set an environment variable `SESSION_SECRET` in Render for security.
- Port is read from `process.env.PORT` (Render provides it automatically).
- For production, replace JSON storage with a proper DB like MongoDB.

# websocket
