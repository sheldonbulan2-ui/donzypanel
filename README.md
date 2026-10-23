# Donzy Admin Panel & Validation Server

A complete Web-based Admin & Super Admin Management Panel with client validation API, powered by **TiDB Cloud (MySQL Serverless)** and designed for seamless deployment on **Render**.

---

## 🚀 Features

- **Role-Based Access Control (RBAC):**
  - **Super Admin (`super_admin`):** Full control. Can create/delete sub-admins and client users.
  - **Admin (`admin`):** Can manage user access, activate/suspend licenses, and set expiration dates.
- **Client Access Validation Endpoint:**
  - Secure `/api/validate` route verifying credentials with `bcrypt` against TiDB Cloud.
  - Prevents unauthorized access or random logins.
- **Modern Responsive Dashboard:**
  - Dark-mode, Stitch-themed UI (`#0b0f19`, Sky Cyan `#38bdf8`, Pink `#f472b6`).
- **Render Ready:**
  - Includes `render.yaml` for 1-click cloud deployment.

---

## 📋 Default Credentials

- **Super Admin Username:** `superadmin`
- **Default Password:** `admin123`
*(Make sure to change the password once logged in or create your own custom super admin).*

---

## 🛠️ Local Setup

1. **Install Dependencies:**
   ```bash
   npm install
   ```

2. **Configure Environment:**
   Copy `.env.example` to `.env` and fill in your database credentials:
   ```env
   PORT=3000
   DB_HOST=gateway01.ap-southeast-1.prod.aws.tidbcloud.com
   DB_PORT=4000
   DB_USER=your_user
   DB_PASSWORD=your_password
   DB_NAME=test
   JWT_SECRET=your_secret_key
   ```

3. **Start Server:**
   ```bash
   npm start
   ```
   Open `http://localhost:3000` in your browser.

---

## 🌐 Deploy to Render

1. Create a new Web Service on [Render](https://render.com).
2. Connect your GitHub repository: `https://github.com/sheldonbulan2-ui/donzypanel.git`.
3. In **Environment Variables**, set:
   - `DB_HOST`
   - `DB_PORT`
   - `DB_USER`
   - `DB_PASSWORD`
   - `DB_NAME` (use `test` or your custom TiDB database)
   - `JWT_SECRET`
4. Click **Create Web Service**.

---

## 📡 Client Validation API

Mobile or external clients can validate credentials via:

- **Method:** `POST`
- **URL:** `https://your-render-app.onrender.com/api/validate`
- **Headers:** `Content-Type: application/json`
- **Payload:**
  ```json
  {
    "username": "client_username",
    "password": "client_password"
  }
  ```
- **Responses:**
  - `200 OK`: `{"valid": true, "status": "active", "expires_at": "..."}`
  - `401 Unauthorized`: `{"valid": false, "message": "Invalid credentials."}`
  - `403 Forbidden`: `{"valid": false, "message": "Account is suspended."}`
