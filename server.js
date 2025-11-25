// server.js - enhanced with refresh tokens, user management, order endpoints and CSV export
require('dotenv').config();
const express = require('express');
const app = express();
const path = require('path');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_YOUR_KEY');
const sgMail = require('@sendgrid/mail');
const crypto = require('crypto');
const fs = require('fs');
const csvStringify = require('csv-stringify/lib/sync');

if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_strong_secret';
const DOMAIN = process.env.DOMAIN || 'http://localhost:3000';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Initialize SQLite DB
const dbFile = path.join(__dirname, 'spiceaura.db');
const db = new sqlite3.Database(dbFile);

// Create/alter tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL,
    image TEXT,
    stock INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    reset_token TEXT,
    reset_expires INTEGER,
    refresh_token TEXT,
    refresh_expires INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stripe_session_id TEXT,
    customer_email TEXT,
    amount_total REAL,
    currency TEXT,
    items TEXT,
    status TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )`);
});

// Helper: run SQL with Promise
function runAsync(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err); else resolve(this);
    });
  });
}
function allAsync(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err); else resolve(rows);
    });
  });
}
function getAsync(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err); else resolve(row);
    });
  });
}

// Auth middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({error:'Missing authorization header'});
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({error:'Invalid authorization header'});
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({error:'Invalid token'});
  }
}

// Role check
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({error:'Missing user'});
    if (req.user.role !== role) return res.status(403).json({error:'Forbidden'});
    next();
  };
}

// Create tokens helper
function createTokens(user) {
  const token = jwt.sign({id: user.id, email: user.email, role: user.role}, JWT_SECRET, {expiresIn: '12h'});
  const refresh = crypto.randomBytes(32).toString('hex');
  const refreshExpires = Math.floor(Date.now()/1000) + (60*60*24*30); // 30 days
  return { token, refresh, refreshExpires };
}

// Public endpoints
app.post('/api/register', async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({error:'Missing email or password'});
  try {
    const hashed = await bcrypt.hash(password, 10);
    await runAsync('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hashed, role || 'admin']);
    return res.json({success:true});
  } catch (err) {
    console.error(err);
    return res.status(400).json({error: err.message});
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({error:'Missing'});
  try {
    const user = await getAsync('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(401).json({error:'Invalid credentials'});
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({error:'Invalid credentials'});
    const tokens = createTokens(user);
    // save refresh token
    await runAsync('UPDATE users SET refresh_token=?, refresh_expires=? WHERE id=?', [tokens.refresh, tokens.refreshExpires, user.id]);
    return res.json({token: tokens.token, refresh: tokens.refresh});
  } catch (err) {
    console.error(err);
    res.status(500).json({error: err.message});
  }
});

// Token refresh endpoint
app.post('/api/refresh', async (req, res) => {
  const { refresh } = req.body;
  if (!refresh) return res.status(400).json({error:'Missing refresh token'});
  try {
    const user = await getAsync('SELECT * FROM users WHERE refresh_token = ?', [refresh]);
    if (!user) return res.status(401).json({error:'Invalid refresh token'});
    const now = Math.floor(Date.now()/1000);
    if (!user.refresh_expires || user.refresh_expires < now) return res.status(401).json({error:'Refresh token expired'});
    const tokens = createTokens(user);
    await runAsync('UPDATE users SET refresh_token=?, refresh_expires=? WHERE id=?', [tokens.refresh, tokens.refreshExpires, user.id]);
    return res.json({token: tokens.token, refresh: tokens.refresh});
  } catch (err) {
    console.error(err);
    res.status(500).json({error: err.message});
  }
});

// Password reset request
app.post('/api/request-reset', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({error:'Missing email'});
  try {
    const user = await getAsync('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.json({ok:true}); // Do not reveal whether user exists
    const token = crypto.randomBytes(24).toString('hex');
    const expires = Math.floor(Date.now()/1000) + 60*60; // 1 hour
    await runAsync('UPDATE users SET reset_token=?, reset_expires=? WHERE id=?', [token, expires, user.id]);
    // send email with token link
    if (process.env.SENDGRID_API_KEY) {
      const resetUrl = DOMAIN + '/reset-password.html?token=' + token;
      const msg = {
        to: user.email,
        from: process.env.EMAIL_FROM || 'no-reply@spiceaura.example',
        subject: 'Password reset for SpiceAura',
        text: 'Reset your password: ' + resetUrl,
        html: '<p>Reset your password <a href="'+resetUrl+'">here</a></p>'
      };
      try { await sgMail.send(msg); } catch(e){ console.error('SendGrid error', e); }
    }
    return res.json({ok:true});
  } catch (err) {
    console.error(err);
    res.status(500).json({error: err.message});
  }
});

// Reset password using token
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({error:'Missing'});
  try {
    const now = Math.floor(Date.now()/1000);
    const user = await getAsync('SELECT * FROM users WHERE reset_token = ? AND reset_expires > ?', [token, now]);
    if (!user) return res.status(400).json({error:'Invalid or expired token'});
    const hashed = await bcrypt.hash(password, 10);
    await runAsync('UPDATE users SET password=?, reset_token=NULL, reset_expires=NULL WHERE id=?', [hashed, user.id]);
    return res.json({ok:true});
  } catch (err) {
    console.error(err);
    res.status(500).json({error: err.message});
  }
});

// Users list and role update (admin)
app.get('/api/users', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const users = await allAsync('SELECT id, email, role FROM users ORDER BY id DESC');
    res.json({users});
  } catch (err) { res.status(500).json({error: err.message}); }
});

app.put('/api/users/:id/role', authMiddleware, requireRole('admin'), async (req, res) => {
  const id = req.params.id;
  const { role } = req.body;
  try {
    await runAsync('UPDATE users SET role=? WHERE id=?', [role, id]);
    res.json({success:true});
  } catch (err) { res.status(500).json({error: err.message}); }
});

// Products: public list and protected CRUD
app.get('/api/products', async (req, res) => {
  try {
    const products = await allAsync('SELECT * FROM products ORDER BY id DESC');
    res.json({products});
  } catch (err) {
    res.status(500).json({error:err.message});
  }
});

// Protected product create/update/delete for admin
app.post('/api/products', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, description, price, image, stock } = req.body;
  try {
    const r = await runAsync('INSERT INTO products (name, description, price, image, stock) VALUES (?, ?, ?, ?, ?)', [name, description, price || 0, image || '', stock || 0]);
    res.json({id: r.lastID});
  } catch (err) { res.status(500).json({error:err.message}); }
});

app.put('/api/products/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const id = req.params.id;
  const { name, description, price, image, stock } = req.body;
  try {
    await runAsync('UPDATE products SET name=?, description=?, price=?, image=?, stock=? WHERE id=?', [name, description, price, image, stock, id]);
    res.json({success:true});
  } catch (err) { res.status(500).json({error:err.message}); }
});

app.delete('/api/products/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const id = req.params.id;
  try {
    await runAsync('DELETE FROM products WHERE id=?', [id]);
    res.json({success:true});
  } catch (err) { res.status(500).json({error:err.message}); }
});

// Create Stripe Checkout session from items (items array with id/quantity or name/price)
app.post('/create-checkout-session', async (req, res) => {
  try {
    const { items, customer } = req.body || {};
    // Build line_items
    const line_items = [];
    for (const it of (items || [])) {
      if (it.id) {
        const p = await getAsync('SELECT * FROM products WHERE id = ?', [it.id]);
        if (p) {
          line_items.push({
            price_data: {
              currency: 'usd',
              product_data: { name: p.name, description: p.description || '' },
              unit_amount: Math.round((p.price || 0) * 100)
            },
            quantity: it.quantity || 1
          });
        }
      } else {
        line_items.push({
          price_data: {
            currency: 'usd',
            product_data: { name: it.name || 'Item' },
            unit_amount: Math.round((it.price || 0) * 100)
          },
          quantity: it.quantity || 1
        });
      }
    }

    if (line_items.length === 0) return res.status(400).json({error:'No items to purchase'});

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items,
      mode: 'payment',
      success_url: DOMAIN + '/?payment=success&session_id={CHECKOUT_SESSION_ID}',
      cancel_url: DOMAIN + '/?payment=cancel',
      customer_email: customer && customer.email ? customer.email : undefined,
    });

    res.json({url: session.url, id: session.id});
  } catch (err) {
    console.error(err);
    res.status(500).json({error: err.message});
  }
});

// Stripe webhook endpoint to process checkout.session.completed
app.post('/webhook', bodyParser.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    if (STRIPE_WEBHOOK_SECRET) {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } else {
      event = JSON.parse(req.body.toString());
    }
  } catch (err) {
    console.error('Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    try {
      const lineItems = await stripe.checkout.sessions.listLineItems(session.id, {limit: 100});
      const items = lineItems.data.map(li => ({description: li.description, amount_subtotal: li.amount_subtotal/100, currency: li.currency, quantity: li.quantity}));
      await runAsync('INSERT INTO orders (stripe_session_id, customer_email, amount_total, currency, items, status) VALUES (?, ?, ?, ?, ?, ?)', [
        session.id,
        session.customer_email || session.customer || '',
        (session.amount_total || 0)/100,
        session.currency || 'usd',
        JSON.stringify(items),
        'paid'
      ]);
      if (process.env.SENDGRID_API_KEY) {
        const msg = {
          to: session.customer_email || session.customer || 'unknown@domain',
          from: process.env.EMAIL_FROM || 'no-reply@spiceaura.example',
          subject: 'Order confirmation - SpiceAura',
          text: 'Thank you for your order. Order ID: ' + session.id,
          html: '<p>Thank you for your order. Order ID: ' + session.id + '</p><pre>' + JSON.stringify(items, null, 2) + '</pre>'
        };
        try { await sgMail.send(msg); } catch(e){ console.error('SendGrid send error', e); }
      }
      console.log('Order recorded for session', session.id);
    } catch (e) {
      console.error('Error processing checkout.session.completed', e);
    }
  }

  res.json({received: true});
});

// Orders endpoints (admin)
app.get('/api/orders', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const orders = await allAsync('SELECT * FROM orders ORDER BY id DESC');
    res.json({orders});
  } catch (err) {
    res.status(500).json({error:err.message});
  }
});

app.get('/api/orders/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const o = await getAsync('SELECT * FROM orders WHERE id=?', [req.params.id]);
    if (!o) return res.status(404).json({error:'Not found'});
    res.json({order: o});
  } catch (err) { res.status(500).json({error: err.message}); }
});

// CSV export
app.get('/api/orders.csv', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const orders = await allAsync('SELECT * FROM orders ORDER BY id DESC');
    const rows = orders.map(o => ({
      id: o.id,
      stripe_session_id: o.stripe_session_id,
      customer_email: o.customer_email,
      amount_total: o.amount_total,
      currency: o.currency,
      items: o.items,
      status: o.status,
      created_at: new Date(o.created_at*1000).toISOString()
    }));
    const csv = csvStringify(rows, {header:true});
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="orders.csv"');
    res.send(csv);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
});

// Serve index and admin files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server running on port', port));
