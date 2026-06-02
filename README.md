# HoneyNet - API Honeypot & Threat Intelligence Dashboard

This is a personal project I built to learn about async Python, WebSockets, and threat intelligence. It's a fully asynchronous Python honeypot that captures attacker activity, enriches the data with GeoIP lookups, saves it to an SQLite database, and streams it all to a dark-theme dashboard in real time. 

I built this phase-by-phase as a portfolio piece to get hands-on experience with FastAPI, SQLAlchemy, and frontend development without frameworks.

---

## Tech Stack

Here's what I used to build this:

- **FastAPI (async)**: Chosen for its native ASGI support, WebSockets, and auto-generated docs.
- **Uvicorn + uvloop**: An incredibly fast event-loop server to handle thousands of concurrent WebSocket connections.
- **SQLite + aiosqlite**: I wanted zero-setup persistence, but with async I/O to prevent blocking the event loop.
- **SQLAlchemy 2.x**: For typed models and async database sessions.
- **httpx (async)**: For doing GeoIP lookups with a shared connection pool.
- **Vanilla HTML/CSS/JS**: I decided to skip frontend frameworks like React to have full control and keep things lightweight.
- **Nginx**: Used as a reverse proxy for TLS termination, WebSocket upgrades, and static caching.
- **systemd**: To keep the service running on my Linux server with auto-restarts and logging.

---

## Project Structure

Here is a quick look at how I organized the code:

```
honeypot/
├── app/
│   ├── main.py                 # FastAPI app, lifespan, middleware, routers
│   ├── config.py               # Settings singleton
│   ├── database.py             # Async SQLAlchemy engine
│   ├── engine/                 # Threat detection logic (signatures, behavioral)
│   ├── middleware/             # ASGI body-replay middleware
│   ├── models/                 # SQLAlchemy ORM models
│   ├── routers/                # API endpoints and WebSocket routes
│   └── services/               # GeoIP, event storage, connection management
├── static/                     # Vanilla HTML, CSS, JS dashboard
├── nginx/                      # Nginx reverse proxy configuration
├── deploy.sh                   # EC2 Ubuntu setup script
├── requirements.txt            # Python dependencies
└── scripts/                    # Machine learning training scripts
```

---

## How I Built It

I tackled this project in a few distinct phases to keep things manageable.

### Phase 1: Core Setup
I started by setting up the basic FastAPI server, configuring the async database engine, and adding health probes. Getting the async lifecycle management right was a fun challenge.

### Phase 2: Threat Engine & Deceptive Routes
Next, I added the actual honeypot endpoints. I created fake routes like `/wp-admin`, `/.env`, and `/api/v1/users` that return realistic-looking dummy data to attackers. I also wrote an ASGI middleware that intercepts every request and passes it through a signature scanner and a behavioral rate-limiter to assign a threat level.

### Phase 3: Data Persistence & Enrichment
Once I was catching attacks, I needed to store them. I hooked up an async GeoIP service to find out where the attacks were coming from, and wrote the ORM models to save everything to SQLite.

### Phase 4: Real-Time WebSockets
To make it feel alive, I added a WebSocket connection manager. Now, whenever an attack is saved to the database, it immediately broadcasts to any open dashboard tabs.

### Phase 5: The Dashboard & Production Deployment
Finally, I built a custom dark-theme dashboard using vanilla CSS and JavaScript to visualize the attacks. I then deployed the whole stack to an AWS EC2 instance using Nginx and systemd.

### Phase 6: Machine Learning Anomaly Detection
To catch zero-day attacks that my static regex signatures miss, I added an unsupervised Machine Learning layer. I wrote a standalone script using pandas and scikit-learn to train an Isolation Forest model on historical traffic, and hooked it into the live FastAPI middleware to score incoming requests on the fly.

---

## Running It Locally

If you want to spin this up yourself:

```bash
# 1. Create a virtual environment
python3 -m venv venv && source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
python -m app.main

# 4. Open the dashboard
open http://localhost:8000

# 5. Fire some test attacks in another terminal to see it light up!
for route in /.env /wp-admin /admin /phpinfo.php; do
  curl -s http://localhost:8000$route -o /dev/null
done
```
