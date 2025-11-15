// server.js
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs-extra');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 10000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads', 'pending');
const APPROVED_DIR = path.join(__dirname, 'uploads', 'approved');
const RSA_KEY_DIR = path.join(__dirname, 'data');
const RSA_PRIVATE_KEY_FILE = path.join(RSA_KEY_DIR, 'rsa_private_key.pem');
const RSA_PUBLIC_KEY_FILE = path.join(RSA_KEY_DIR, 'rsa_public_key.pem');

fs.ensureDirSync(DATA_DIR);
fs.ensureDirSync(UPLOAD_DIR);
fs.ensureDirSync(APPROVED_DIR);
fs.ensureDirSync(RSA_KEY_DIR);

// RSA Key Management
let rsaPrivateKey = null;
let rsaPublicKey = null;

// Generate or load RSA keys (2048 bits minimum)
function initializeRSAKeys() {
  try {
    if (fs.existsSync(RSA_PRIVATE_KEY_FILE) && fs.existsSync(RSA_PUBLIC_KEY_FILE)) {
      // Load existing keys
      rsaPrivateKey = fs.readFileSync(RSA_PRIVATE_KEY_FILE, 'utf8');
      rsaPublicKey = fs.readFileSync(RSA_PUBLIC_KEY_FILE, 'utf8');
      console.log('Loaded existing RSA keys');
    } else {
      // Generate new RSA key pair (2048 bits)
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
      
      rsaPrivateKey = privateKey;
      rsaPublicKey = publicKey;
      
      // Save keys to files (private key should be protected in production)
      fs.writeFileSync(RSA_PRIVATE_KEY_FILE, privateKey, { mode: 0o600 });
      fs.writeFileSync(RSA_PUBLIC_KEY_FILE, publicKey, { mode: 0o644 });
      console.log('Generated new RSA key pair (2048 bits)');
    }
  } catch (error) {
    console.error('Error initializing RSA keys:', error);
    throw error;
  }
}

// Initialize RSA keys on startup
initializeRSAKeys();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}_${uuidv4()}_${file.originalname}`;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage: storage });

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false
}));

// Read and write users
function readUsers() {
  return fs.existsSync(USERS_FILE) ? fs.readJsonSync(USERS_FILE) : {};
}

function writeUsers(users) {
  fs.writeJsonSync(USERS_FILE, users, { spaces: 2 });
}

// RSA encryption/decryption functions
// RSA-OAEP can encrypt max ~214 bytes per chunk for 2048-bit keys
const RSA_MAX_CHUNK_SIZE = 214; // bytes per chunk (accounting for OAEP padding)

function encryptMessageRSA(message, publicKeyPem) {
  try {
    const messageBuffer = Buffer.from(message, 'utf8');
    const chunks = [];
    
    // Split message into chunks if it's too large
    for (let i = 0; i < messageBuffer.length; i += RSA_MAX_CHUNK_SIZE) {
      const chunk = messageBuffer.slice(i, i + RSA_MAX_CHUNK_SIZE);
      const encryptedChunk = crypto.publicEncrypt(
        {
          key: publicKeyPem,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        chunk
      );
      // Convert to URL-safe base64 for JSON transport
      chunks.push(encryptedChunk.toString('base64'));
    }
    
    return {
      encryptedData: chunks,
      algorithm: 'RSA-OAEP-2048'
    };
  } catch (error) {
    console.error('RSA encryption error:', error);
    throw error;
  }
}

function decryptMessageRSA(encryptedObj) {
  try {
    if (!encryptedObj.encryptedData || !Array.isArray(encryptedObj.encryptedData)) {
      throw new Error('Invalid encrypted data format');
    }
    
    if (!rsaPrivateKey) {
      throw new Error('RSA private key not initialized');
    }
    
    const decryptedChunks = [];
    
    // Decrypt each chunk
    for (const encryptedChunkBase64 of encryptedObj.encryptedData) {
      const encryptedChunk = Buffer.from(encryptedChunkBase64, 'base64');
      const decryptedChunk = crypto.privateDecrypt(
        {
          key: rsaPrivateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        encryptedChunk
      );
      decryptedChunks.push(decryptedChunk);
    }
    
    // Combine all decrypted chunks
    const fullMessage = Buffer.concat(decryptedChunks);
    return fullMessage.toString('utf8');
  } catch (error) {
    console.error('RSA decryption error:', error);
    return null;
  }
}

// Legacy AES decryption functions (for backward compatibility with old messages)
function deriveChatKey(pin1, pin2) {
  // Create a shared key from both users' PINs
  const combined = [pin1, pin2].sort().join(''); // Sort for consistency
  return crypto.createHash('sha256').update(combined).digest('hex');
}

function decryptMessageAES(encryptedObj, key) {
  try {
    if (!encryptedObj.iv || !encryptedObj.encryptedData) {
      return null;
    }
    const algorithm = 'aes-256-cbc';
    const iv = Buffer.from(encryptedObj.iv, 'hex');
    const encryptedData = encryptedObj.encryptedData;
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('AES decryption error:', e);
    return null;
  }
}

// Universal decrypt function that detects message format and uses appropriate method
function decryptMessageUniversal(encryptedObj, pin1 = null, pin2 = null) {
  // Detect message format
  if (encryptedObj.algorithm === 'RSA-OAEP-2048' || Array.isArray(encryptedObj.encryptedData)) {
    // RSA format - no PINs needed
    return decryptMessageRSA(encryptedObj);
  } else if (encryptedObj.iv && typeof encryptedObj.encryptedData === 'string') {
    // Legacy AES format - need PINs
    if (!pin1 || !pin2) {
      console.error('AES decryption requires PINs but none provided');
      return null;
    }
    const chatKey = deriveChatKey(pin1, pin2);
    return decryptMessageAES(encryptedObj, chatKey);
  } else {
    console.error('Unknown encryption format:', encryptedObj);
    return null;
  }
}

function getChatFileName(user1, user2) {
  // Create consistent filename regardless of order
  const users = [user1, user2].sort();
  return path.join(DATA_DIR, `${users[0]}_${users[1]}_chat.json`);
}

function getEncryptedChatFileName(user1, user2) {
  const users = [user1, user2].sort();
  return path.join(DATA_DIR, `${users[0]}_${users[1]}_chat.enc`);
}

function readChat(user1, user2) {
  const chatFile = getChatFileName(user1, user2);
  return fs.existsSync(chatFile) ? fs.readJsonSync(chatFile) : [];
}

function writeChat(user1, user2, messages) {
  const chatFile = getChatFileName(user1, user2);
  fs.writeJsonSync(chatFile, messages, { spaces: 2 });
  
  // Also write encrypted version
  const encFile = getEncryptedChatFileName(user1, user2);
  fs.writeJsonSync(encFile, messages, { spaces: 2 });
}

// Signup endpoint
app.post('/signup', (req, res) => {
  const { username, password, password2 } = req.body;
  if (!username || !password || password !== password2) {
    return res.status(400).send('Invalid input or passwords do not match.');
  }
  const users = readUsers();
  if (users[username]) return res.status(400).send('Username already exists.');
  const hashed = bcrypt.hashSync(password, 10);
  users[username] = { password: hashed };
  writeUsers(users);
  res.redirect('/dashboard.html');
});

// Whoami endpoint - check if user is logged in
app.get('/api/whoami', (req, res) => {
  if (req.session.user) {
    return res.json({ user: req.session.user });
  }
  return res.status(401).json({ error: 'Not authenticated' });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.redirect('/login.html?error=' + encodeURIComponent('Username and password are required.'));
  }
  
  const users = readUsers();
  
  if (!users[username]) {
    return res.redirect('/login.html?error=' + encodeURIComponent('Invalid username or password.'));
  }
  
  // Check if user has a valid password hash
  if (!users[username].password) {
    return res.redirect('/login.html?error=' + encodeURIComponent('Invalid username or password.'));
  }
  
  if (!bcrypt.compareSync(password, users[username].password)) {
    return res.redirect('/login.html?error=' + encodeURIComponent('Invalid username or password.'));
  }
  
  req.session.user = username;
  res.redirect('/dashboard.html');
});

// Logout endpoint
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// Get user data endpoint
app.get('/api/user-data', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  // Return user data without password
  const { password, ...userData } = user;
  res.json(userData);
});

// Approve file endpoint
app.post('/api/approve/:fileId', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const fileId = req.params.fileId;
  const pendingIndex = user.pending ? user.pending.findIndex(f => f.id === fileId) : -1;
  
  if (pendingIndex === -1) {
    return res.status(404).json({ error: 'File not found in pending' });
  }
  
  const file = user.pending[pendingIndex];
  const pendingPath = path.join(UPLOAD_DIR, file.storedName);
  const approvedPath = path.join(APPROVED_DIR, file.storedName);
  
  // Move file from pending to approved directory
  if (fs.existsSync(pendingPath)) {
    fs.moveSync(pendingPath, approvedPath, { overwrite: true });
  }
  
  user.pending.splice(pendingIndex, 1);
  if (!user.files) user.files = [];
  user.files.push(file);
  
  // Update status in sender's sentFiles if sender exists
  if (file.sender && file.sender !== 'Anonymous') {
    // Find the sender and update their sent file status
    Object.keys(users).forEach(username => {
      const senderUser = users[username];
      if (senderUser.sentFiles) {
        const sentFileIndex = senderUser.sentFiles.findIndex(f => f.id === fileId);
        if (sentFileIndex !== -1) {
          senderUser.sentFiles[sentFileIndex].status = 'approved';
        }
      }
    });
  }
  
  writeUsers(users);
  res.json({ success: true });
});

// Reject file endpoint
app.post('/api/reject/:fileId', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const fileId = req.params.fileId;
  let rejectedFile = null;
  
  if (user.pending) {
    const pendingIndex = user.pending.findIndex(f => f.id === fileId);
    if (pendingIndex !== -1) {
      rejectedFile = user.pending[pendingIndex];
      user.pending.splice(pendingIndex, 1);
      
      // Update status in sender's sentFiles if sender exists
      if (rejectedFile.sender && rejectedFile.sender !== 'Anonymous') {
        Object.keys(users).forEach(username => {
          const senderUser = users[username];
          if (senderUser.sentFiles) {
            const sentFileIndex = senderUser.sentFiles.findIndex(f => f.id === fileId);
            if (sentFileIndex !== -1) {
              senderUser.sentFiles[sentFileIndex].status = 'rejected';
            }
          }
        });
      }
      
      writeUsers(users);
    }
  }
  res.json({ success: true });
});

// Download file endpoint
app.get('/api/download/:fileId', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Not authenticated');
  }
  const users = readUsers();
  const user = users[req.session.user];
  if (!user || !user.files) return res.status(404).send('File not found');
  
  const fileId = req.params.fileId;
  const file = user.files.find(f => f.id === fileId);
  if (!file) return res.status(404).send('File not found');
  
  const filePath = path.join(__dirname, 'uploads', 'approved', file.storedName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found on disk');
  }
  res.download(filePath, file.filename);
});

// Upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
  const { receiver, pin, sender } = req.body;
  const file = req.file;
  
  if (!receiver || !pin || !file) {
    return res.status(400).send('Missing required fields: receiver, pin, or file');
  }
  
  const users = readUsers();
  const receiverUser = users[receiver];
  
  if (!receiverUser) {
    return res.status(404).send('Receiver not found');
  }
  
  if (receiverUser.pin !== pin) {
    return res.status(401).send('Invalid PIN');
  }
  
  // Determine sender username (use session if available, otherwise use sender name from form)
  const senderUsername = req.session.user || sender || 'Anonymous';
  
  // Create file entry
  const fileEntry = {
    id: uuidv4(),
    filename: file.originalname,
    storedName: file.filename,
    sender: sender || 'Anonymous',
    time: new Date().toISOString()
  };
  
  // Add to receiver's pending files
  if (!receiverUser.pending) receiverUser.pending = [];
  receiverUser.pending.push(fileEntry);
  
  // Track sent file in sender's account (if sender is logged in)
  if (req.session.user && users[req.session.user]) {
    const senderUser = users[req.session.user];
    if (!senderUser.sentFiles) senderUser.sentFiles = [];
    
    const sentFileEntry = {
      id: fileEntry.id,
      filename: file.originalname,
      receiver: receiver,
      receiverUsername: receiver,
      senderName: sender || req.session.user,
      time: fileEntry.time,
      status: 'pending' // pending, approved, rejected
    };
    
    senderUser.sentFiles.push(sentFileEntry);
  }
  
  writeUsers(users);
  
  res.send('File uploaded successfully');
});

// Update PIN endpoint
app.post('/api/update-pin', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const { pin } = req.body;
  
  if (!pin || !/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
  }
  
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  user.pin = pin;
  writeUsers(users);
  res.json({ success: true });
});

// Generate or retrieve user RSA key pair endpoint
app.get('/api/user-keys', (req, res) => {
  console.log('GET /api/user-keys - Request received');
  
  if (!req.session.user) {
    console.log('GET /api/user-keys - Not authenticated');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  console.log('GET /api/user-keys - User:', req.session.user);
  
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) {
    console.log('GET /api/user-keys - User not found in database');
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Generate key pair if user doesn't have one
  if (!user.rsaKeyPair) {
    try {
      console.log(`Generating RSA key pair for user: ${req.session.user}`);
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
      
      if (!publicKey || !privateKey) {
        throw new Error('Key generation returned null keys');
      }
      
      user.rsaKeyPair = {
        publicKey: publicKey,
        privateKey: privateKey
      };
      
      writeUsers(users);
      console.log(`Successfully generated RSA key pair for user: ${req.session.user}`);
    } catch (error) {
      console.error('Error generating key pair:', error);
      console.error('Error stack:', error.stack);
      return res.status(500).json({ 
        error: 'Failed to generate key pair: ' + error.message 
      });
    }
  }
  
  // Return both keys
  res.json({
    publicKey: user.rsaKeyPair.publicKey,
    privateKey: user.rsaKeyPair.privateKey
  });
});

// Regenerate user RSA key pair endpoint
app.post('/api/user-keys', (req, res) => {
  console.log('POST /api/user-keys - Request received');
  
  if (!req.session.user) {
    console.log('POST /api/user-keys - Not authenticated');
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  console.log('POST /api/user-keys - User:', req.session.user);
  
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) {
    console.log('POST /api/user-keys - User not found in database');
    return res.status(404).json({ error: 'User not found' });
  }
  
  try {
    console.log(`Regenerating RSA key pair for user: ${req.session.user}`);
    
    // Generate new key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    if (!publicKey || !privateKey) {
      throw new Error('Key generation returned null keys');
    }
    
    // Replace old key pair
    user.rsaKeyPair = {
      publicKey: publicKey,
      privateKey: privateKey
    };
    
    writeUsers(users);
    
    console.log(`Successfully regenerated RSA key pair for user: ${req.session.user}`);
    
    // Return new keys
    res.json({
      publicKey: user.rsaKeyPair.publicKey,
      privateKey: user.rsaKeyPair.privateKey
    });
  } catch (error) {
    console.error('Error regenerating key pair:', error);
    console.error('Error stack:', error.stack);
    return res.status(500).json({ 
      error: 'Failed to regenerate key pair: ' + error.message 
    });
  }
});

// Get recipient's public key endpoint
app.get('/api/user/:username/public-key', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const username = req.params.username;
  const users = readUsers();
  const user = users[username];
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Generate key pair if user doesn't have one
  if (!user.rsaKeyPair) {
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
      
      user.rsaKeyPair = {
        publicKey: publicKey,
        privateKey: privateKey
      };
      
      writeUsers(users);
      console.log(`Auto-generated RSA key pair for user: ${username}`);
    } catch (error) {
      console.error('Error generating key pair:', error);
      return res.status(500).json({ error: 'Failed to generate key pair' });
    }
  }
  
  // Return only public key (safe to share)
  res.json({
    publicKey: user.rsaKeyPair.publicKey,
    username: username
  });
});

// Update user public key (for sharing with others)
app.post('/api/update-public-key', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { publicKey } = req.body;
  if (!publicKey) {
    return res.status(400).json({ error: 'Public key is required' });
  }
  
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  if (!user.rsaKeyPair) {
    user.rsaKeyPair = {};
  }
  
  user.rsaKeyPair.publicKey = publicKey;
  writeUsers(users);
  
  res.json({ success: true });
});

// Get sent files endpoint
app.get('/api/sent-files', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const users = readUsers();
  const user = users[req.session.user];
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const sentFiles = user.sentFiles || [];
  res.json(sentFiles);
});

// Get RSA public key endpoint (for clients to encrypt messages)
app.get('/api/rsa-public-key', (req, res) => {
  if (!rsaPublicKey) {
    return res.status(500).json({ error: 'RSA public key not available' });
  }
  res.json({ publicKey: rsaPublicKey });
});

// Get chat messages endpoint
app.get('/api/chat/:recipient', (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const sender = req.session.user;
    const recipient = req.params.recipient;
    const users = readUsers();
    
    if (!users[sender]) {
      return res.status(404).json({ error: 'Your account not found' });
    }
    
    // If recipient doesn't exist, still return empty messages (might be deleted user)
    if (!users[recipient]) {
      return res.json({
        messages: [],
        sender: sender,
        recipient: recipient,
        warning: 'Recipient user not found'
      });
    }
    
    // Read messages (they are RSA encrypted on disk)
    let messages = [];
    try {
      messages = readChat(sender, recipient);
    } catch (err) {
      console.error('Error reading chat:', err);
      messages = [];
    }
    
    // Return messages (encrypted with RSA - server will decrypt when requested)
    res.json({
      messages: messages,
      sender: sender,
      recipient: recipient
    });
  } catch (err) {
    console.error('Error in get chat messages:', err);
    res.status(500).json({ error: 'Failed to load messages: ' + err.message });
  }
});

// Send chat message endpoint
app.post('/api/chat/send', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { recipient, message, recipientPin, encrypted, encryptedFormat } = req.body;
  const sender = req.session.user;
  
  if (!recipient || !message) {
    return res.status(400).json({ error: 'Missing required fields: recipient and message' });
  }
  
  const users = readUsers();
  
  if (!users[sender] || !users[recipient]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // PIN verification is optional now (only for backward compatibility with old messages)
  if (recipientPin) {
    const recvPin = users[recipient].pin || '';
    if (recvPin && recvPin !== recipientPin) {
      return res.status(401).json({ error: 'Invalid recipient PIN' });
    }
  }
  
  // Handle message encryption
  let encryptedMessage;
  if (encrypted && Array.isArray(message)) {
    // Client has already encrypted the message with recipient's public key
    encryptedMessage = {
      encryptedData: message,
      algorithm: 'RSA-OAEP-2048',
      format: encryptedFormat || 'rsa-e2e' // End-to-end RSA
    };
  } else if (encrypted && typeof message === 'object' && message.encryptedData) {
    // Already in encrypted format (full object)
    encryptedMessage = message;
  } else if (typeof message === 'string') {
    // Plain text message - for backward compatibility, but this shouldn't happen in new flow
    // In new flow, client should encrypt before sending
    encryptedMessage = {
      message: message, // Store as plaintext temporarily (not recommended)
      encrypted: false
    };
  } else {
    // Already in encrypted format
    encryptedMessage = message;
  }
  
  // Create message object
  const messageObj = {
    id: uuidv4(),
    from: sender,
    to: recipient,
    message: encryptedMessage, // Store encrypted
    time: new Date().toISOString(),
    encrypted: true
  };
  
  // Save to chat file
  const messages = readChat(sender, recipient);
  messages.push(messageObj);
  writeChat(sender, recipient, messages);
  
  res.json({ success: true, messageId: messageObj.id });
});

// Get chat conversations list
app.get('/api/chat/conversations', (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const currentUser = req.session.user;
    const users = readUsers();
    const conversations = [];
    
    // Find all chat files for this user
    let chatFiles = [];
    try {
      if (fs.existsSync(DATA_DIR)) {
        chatFiles = fs.readdirSync(DATA_DIR).filter(f => 
          f.includes('_chat.json') && f.includes(currentUser)
        );
      }
    } catch (err) {
      console.error('Error reading chat directory:', err);
      return res.json([]); // Return empty array if directory read fails
    }
    
    chatFiles.forEach(file => {
      try {
        const parts = file.replace('_chat.json', '').split('_');
        if (parts.length < 2) return; // Skip invalid filenames
        
        const otherUser = parts[0] === currentUser ? parts[1] : parts[0];
        
        // Include conversation even if user doesn't exist (might be deleted)
        // This allows viewing old messages
        let messages = [];
        try {
          messages = readChat(currentUser, otherUser);
        } catch (err) {
          console.error(`Error reading chat with ${otherUser}:`, err);
          messages = [];
        }
        
        const lastMessage = messages.length > 0 ? messages[messages.length - 1] : null;
        
        let preview = '[Encrypted]';
        if (lastMessage) {
          if (lastMessage.message && typeof lastMessage.message === 'object' && lastMessage.message.encryptedData) {
            preview = '[Encrypted]';
          } else if (typeof lastMessage.message === 'string') {
            preview = lastMessage.message.substring(0, 50);
          }
        }
        
        conversations.push({
          username: otherUser,
          lastMessage: lastMessage ? {
            preview: preview,
            time: lastMessage.time
          } : null,
          unreadCount: 0,
          userExists: !!users[otherUser] // Flag to indicate if user still exists
        });
      } catch (err) {
        console.error(`Error processing chat file ${file}:`, err);
        // Continue with other files
      }
    });
    
    res.json(conversations);
  } catch (err) {
    console.error('Error in conversations endpoint:', err);
    res.status(500).json({ error: 'Failed to load conversations: ' + err.message });
  }
});

// Decrypt message endpoint (for backward compatibility with old AES messages only)
// Note: New RSA messages should be decrypted client-side with user's private key
app.post('/api/chat/decrypt', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { recipient, encryptedMessage, recipientPin } = req.body;
  const sender = req.session.user;
  
  if (!recipient || !encryptedMessage) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const users = readUsers();
  if (!users[sender] || !users[recipient]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Only decrypt old AES messages server-side
  // New RSA messages should be decrypted client-side
  if (encryptedMessage.format === 'rsa-e2e' || (Array.isArray(encryptedMessage.encryptedData) && encryptedMessage.algorithm === 'RSA-OAEP-2048')) {
    return res.status(400).json({ error: 'RSA messages must be decrypted client-side using your private key' });
  }
  
  // Get PINs for backward compatibility with AES-encrypted messages
  const senderPin = users[sender].pin || '';
  const recvPin = users[recipient].pin || recipientPin || '';
  
  // Try to decrypt using universal decrypt function (only for old AES messages)
  let decrypted = null;
  try {
    decrypted = decryptMessageUniversal(encryptedMessage, senderPin, recvPin);
  } catch (error) {
    console.error('Decryption error:', error);
    return res.status(400).json({ error: 'Failed to decrypt: ' + error.message });
  }
  
  if (!decrypted) {
    return res.status(400).json({ error: 'Failed to decrypt - may need recipient PIN for old AES messages' });
  }
  
  res.json({ decrypted });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
