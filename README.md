SpiceAura — Ready-to-publish package
===================================

What I changed
--------------
- Fixed a JavaScript bug in cart addition (used spread operator instead of invalid token).
- Normalized checkout button "Processing Payment..." text.
- Added inline comment in the mock API.placeOrder to explain how to replace it with a real gateway call.
- Packaged the modified site as index.html and added example server + README to integrate Stripe or PayPal.

Files included
--------------
- index.html           (fixed, ready to host as a static site)
- server.js            (example Node/Express server implementing Stripe Checkout session)
- package.json         (for the example server)
- README.md            (this file)
- LICENSE.txt          (MIT license stub)

Quick hosting options
---------------------
1) Static hosting (recommended for easiest publish): Netlify, Vercel, GitHub Pages, Surge.
   - If you don't need server-side payments, you can deploy index.html directly.
   - For Netlify/Vercel: connect a GitHub repo or drag-and-drop the folder in their UI.

2) Full hosting with payments (recommended): Use a small Node/Express server (example server.js included).
   - Host on services like Render, Railway, Heroku (paid dynos for production), DigitalOcean App Platform, or a VPS.
   - The server example shows how to create a Stripe Checkout Session. You must set STRIPE_SECRET_KEY and DOMAIN environment variables.

Payment gateway integration (summary)
------------------------------------
- Stripe Checkout (recommended for e-commerce):
  1. Create a Stripe account and get your secret key (STRIPE_SECRET_KEY) and publishable key (STRIPE_PUB_KEY).
  2. Deploy the included server.js and set STRIPE_SECRET_KEY and DOMAIN (e.g. https://yourdomain.com).
  3. Client (index.html) should POST the order to /create-checkout-session on your server. Server creates Session and returns sessionId.
  4. Client redirects to Stripe Checkout using stripe.redirectToCheckout({ sessionId }).

- PayPal (alternative):
  1. Use PayPal Checkout SDK; you can integrate client-only buttons in sandbox for simple flows, but server-side order capture is recommended.
  2. PayPal requires server endpoints to securely create orders in production (use CLIENT ID / SECRET on server).

Security & Admin notes
----------------------
- The admin dashboard in index.html is a mock using localStorage with mock users (admin@spiceaura.com / admin).
- For production you MUST implement server-side authentication, secure password storage (bcrypt), and a database (Postgres, MongoDB, etc.).
- Protect admin endpoints with authentication & role-based access control (JWT or server sessions).
- Do NOT rely on client-side checks for security (they are easily bypassed).

How to run the included example server (local test)
--------------------------------------------------
1) Install Node >= 16
2) Copy the folder to your machine and run:
     npm install
3) Create a .env with:
     STRIPE_SECRET_KEY=sk_test_xxx
     DOMAIN=http://localhost:3000
4) Start the server:
     node server.js
5) Open http://localhost:3000 to view the site; the server exposes /create-checkout-session example endpoint for Stripe.

Next steps I can do (tell me which you want and I'll apply directly):
---------------------------------------------------------------------
- Replace the mock API.placeOrder in index.html with direct calls to the example server and client-side Stripe integration.
- Add server-side product management (CRUD) and persist products to a database.
- Add secure user registration/login and password reset flows.
- Add transactional emails (order confirmation) via SendGrid or similar.
- Optimize images, add sitemap, robots.txt, and SEO meta tags.

License
-------
MIT License - use freely for development. See LICENSE.txt


## Full server & features applied

- Admin register/login endpoints: POST /api/register, POST /api/login
- Products CRUD: /api/products (GET), POST /api/products (admin), PUT/DELETE /api/products/:id (admin)
- Stripe Checkout: POST /create-checkout-session -> returns {url}
- SQLite DB file: spiceaura.db (created automatically)

### Environment variables required for full features
- STRIPE_SECRET_KEY=sk_test_xxx
- DOMAIN=https://yourdomain.com (or http://localhost:3000)
- JWT_SECRET=replace_with_long_random
- SENDGRID_API_KEY=your_sendgrid_key (optional, for emails)

### How to run locally
1. Install Node.js (>=16)
2. In the folder, run `npm install`
3. Create a `.env` with the variables above
4. Run `npm start`
5. Visit `http://localhost:3000`

Notes:
- The /api/register endpoint will create an admin user. Remove or protect it after initial setup in production.
- Implement a webhook for Stripe (checkout.session.completed) to verify payments server-side and send order confirmation emails.


## Webhook and password reset

- Configure `STRIPE_WEBHOOK_SECRET` for secure webhook signature verification.
- Webhook endpoint: POST /webhook . Use Stripe CLI or dashboard to register the webhook URL.
- Orders are recorded in the `orders` table on `checkout.session.completed`.
- Password reset flow: POST /api/request-reset with {email}, user gets email (if SendGrid configured) with reset link to `/reset-password.html?token=...`.

## Stripe CLI & Webhook testing (recommended for local dev)

1. Install Stripe CLI: https://stripe.com/docs/stripe-cli
2. Start listening and forward events to your local webhook endpoint:
   stripe listen --forward-to localhost:3000/webhook
3. Copy the webhook signing secret shown by the CLI and set it as STRIPE_WEBHOOK_SECRET in your .env file.
4. Create a test Checkout session from the UI and complete payment in Stripe's test mode. The webhook will be forwarded to `/webhook` and processed by the server.

You can also send a test event:
   stripe trigger checkout.session.completed

## Deployment configs included
- Dockerfile (container image)
- Procfile (Heroku)
- render.yaml (Render.com)

### Quick deployment notes
- For Heroku: create app, set env vars (STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, DOMAIN, JWT_SECRET, SENDGRID_API_KEY, EMAIL_FROM), push repository. Heroku will use Procfile.
- For Render: connect your GitHub repo and use the included render.yaml to configure the service. Add environment variables in the Render dashboard.
- For container-based deploy (Docker): build `docker build -t spiceaura .` and `docker run -e STRIPE_SECRET_KEY=... -p 3000:3000 spiceaura`

