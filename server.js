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

fs.ensureDirSync(DATA_DIR);
fs.ensureDirSync(UPLOAD_DIR);
fs.ensureDirSync(APPROVED_DIR);

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

// Chat encryption/decryption functions
function encryptMessage(message, key) {
  const algorithm = 'aes-256-cbc';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
}

function decryptMessage(encryptedObj, key) {
  try {
    const algorithm = 'aes-256-cbc';
    const iv = Buffer.from(encryptedObj.iv, 'hex');
    const encryptedData = encryptedObj.encryptedData;
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return null;
  }
}

function deriveChatKey(pin1, pin2) {
  // Create a shared key from both users' PINs
  const combined = [pin1, pin2].sort().join(''); // Sort for consistency
  return crypto.createHash('sha256').update(combined).digest('hex');
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
    
    // Read messages (they are encrypted on disk)
    let messages = [];
    try {
      messages = readChat(sender, recipient);
    } catch (err) {
      console.error('Error reading chat:', err);
      messages = [];
    }
    
    // Return messages (client will decrypt)
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
  
  const { recipient, message, recipientPin } = req.body;
  const sender = req.session.user;
  
  if (!recipient || !message || !recipientPin) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const users = readUsers();
  
  if (!users[sender] || !users[recipient]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const senderPin = users[sender].pin || '';
  const recvPin = users[recipient].pin || '';
  
  // Verify recipient PIN
  if (recvPin !== recipientPin) {
    return res.status(401).json({ error: 'Invalid recipient PIN' });
  }
  
  // Derive encryption key from both PINs
  const chatKey = deriveChatKey(senderPin, recvPin);
  
  // Encrypt message
  const encrypted = encryptMessage(message, chatKey);
  
  // Create message object
  const messageObj = {
    id: uuidv4(),
    from: sender,
    to: recipient,
    message: encrypted, // Store encrypted
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

// Decrypt message endpoint (for verification)
app.post('/api/chat/decrypt', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { recipient, encryptedMessage } = req.body;
  const sender = req.session.user;
  
  if (!recipient || !encryptedMessage) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const users = readUsers();
  if (!users[sender] || !users[recipient]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const senderPin = users[sender].pin || '';
  const recvPin = users[recipient].pin || '';
  const chatKey = deriveChatKey(senderPin, recvPin);
  
  const decrypted = decryptMessage(encryptedMessage, chatKey);
  
  if (!decrypted) {
    return res.status(400).json({ error: 'Failed to decrypt' });
  }
  
  res.json({ decrypted });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
