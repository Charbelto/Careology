# Careology: Intelligent Car Dealership Platform

Careology is a production-grade Flask web application designed for car dealership inventory management and customer interactions. It features a complete relational database management system (via SQLite & SQLAlchemy), dynamic CSV parsing of vehicle listings, custom RBAC (Role-Based Access Control) authentication, security protections (CSRF, Content Security Policy, rate-limiting), and an **OpenAI-powered intelligent chatbot assistant** that guides users through inventory queries.

---

## 📋 Table of Contents
1. [Key Features](#-key-features)
2. [Tech Stack](#-tech-stack)
3. [Database Architecture](#-database-architecture)
4. [Intelligent Chatbot Integration](#-intelligent-chatbot-integration)
5. [Security & Protection](#-security--protection)
6. [Installation & Setup](#-installation--setup)

---

## 🎯 Key Features
*   **Inventory Scraping & Ingestion**: Loads scraped listings directly from a local database (`dubizzle.csv`), supporting pagination, pricing formats, and brand filtering.
*   **Authentication & Role Management**:
    *   Secure user registration and login using salted hashes (`pbkdf2:sha256`).
    *   **RBAC System**: Defines permissions (`view_dashboard`, `manage_vehicles`, `manage_users`, `manage_bookings`, `view_reports`) and assigns them to roles (`admin`, `staff`, `user`).
*   **Interactive Search**: Live keyword search and filtering on vehicle makes, model years, fuel types, and price bounds.
*   **Deals & Promotion Page**: Highlights randomly generated active deals from current listings.
*   **Activity Auditing**: Records critical user activities (`login`, `logout`, `register`) along with IP addresses and user agents for security audits.

---

## 💻 Tech Stack
*   **Frontend**: HTML5, Vanilla CSS, FontAwesome, Google Fonts, Bootstrap CSS
*   **Backend**: Flask (Python)
*   **Database**: SQLite with SQLAlchemy ORM
*   **AI Integration**: OpenAI API (GPT-4o-mini engine)
*   **Security**: Flask-Limiter, Werkzeug Security, Cryptography (Fernet/bcrypt)

---

## 🗄 Database Architecture

The system implements a relational database structure:

*   **`User`**: Profiles, email, password hash, role foreign key, activity tracker, failed attempts counter.
*   **`Role`**: Role name (`admin`, `staff`, `user`) and permissions array.
*   **`Permission`**: Specific action flags.
*   **`Vehicle`**: Title, pricing, rental price, mileage, transmission, description, location, source URL.
*   **`VehicleImage`**: Paths to local jpeg assets with a `is_primary` flag.
*   **`UserActivity`**: Logging table tracking action names, timestamps, details, IPs, and user agents.

---

## 🤖 Intelligent Chatbot Integration

Careology features a smart, virtual sales assistant built with **OpenAI GPT-4o-mini**:
*   **Keyword Matcher**: The chatbot parses user input (e.g. "show me Toyotas under 15000") and executes a local query against `dubizzle.csv`.
*   **Hybrid RAG Context**: Matches are structured as text context and sent alongside the user prompt to OpenAI.
*   **Dynamic Visual UI**: The AI response formats and appends matching vehicle cards with photos and link sources directly in the chat panel.

---

## 🛡 Security & Protection

*   **Brute-Force Prevention**: Flask-Limiter enforces rate-limiting (e.g., maximum of 10 login attempts per minute per IP address). Failed attempts trigger account lockout.
*   **Security Headers**: Customized middleware injects robust headers:
    *   `Content-Security-Policy` (strictly white-listing script, style, and image sources).
    *   `X-Content-Type-Options: nosniff`.
    *   `X-Frame-Options: SAMEORIGIN` (prevents clickjacking).
    *   `Strict-Transport-Security`.

---

## 🚀 Installation & Setup

### Prerequisites
*   Python 3.9+
*   An OpenAI API Key (optional, required for Chatbot)

### 1. Setup Environment
```bash
cd github_repos/Careology

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Create a `.env` file in the root of the project:
```env
SECRET_KEY=your_flask_secret_key
DATABASE_URL=sqlite:///database/cars.db
FLASK_ENV=development
OPENAI_API_KEY=your_openai_api_key
```

### 3. Initialize & Run
```bash
# Start Flask server
flask run
```
The app will initialize the database schema on first boot, create default permissions, build default roles, seed sample admin users, and host the client on `http://127.0.0.1:5000/`.
