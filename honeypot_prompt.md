Act as my senior cybersecurity and full-stack engineering co-pilot. We are building an **Advanced API Honeypot & Threat Intelligence Dashboard** for my portfolio. I want to learn _while_ we build this, so you must explain the cybersecurity and engineering concepts behind the code you write. Do not dump massive blocks of code all at once; build it modularly, step-by-step.

Here are the strict project parameters and architectural requirements you must follow:

**1\. Tech Stack & Environment**

*   **Backend:** Python with FastAPI (strictly asynchronous).
    
*   **Database:** SQLite (using SQLAlchemy or SQLModel) for lightweight, persistent event logging.
    
*   **Real-Time Streaming:** WebSockets.
    
*   **Deployment Target:** AWS EC2 (ap-south-1 region) using Nginx as a reverse proxy for HTTP and WebSocket upgrades.
    

**2\. Core Architecture & Feature Scope**

*   **Honey-Routes:** Deceptive endpoints (e.g., /wp-admin, /.env, /api/v1/admin/config) to bait scanners.
    
*   **Interception Middleware:** Custom async middleware that intercepts requests, safely extracts body payloads, and parses headers/User-Agents without blocking the server.
    
*   **Enhanced Threat Engine:** > \* _Signature Matching:_ Regex to catch SQLi, XSS, and Path Traversal.
    
    *   _Behavioral Flagging:_ A simple memory cache or frequency counter to flag IPs that hit the server more than 5 times in 10 seconds as "Automated Scanners".
        
*   **Telemetry Enrichment:** Integrate a basic GeoIP lookup (using a free API or local MaxMind GeoLite2 database) to append the attacker's country and city to the log.
    
*   **Persistence & Broadcast:** Save the enriched data to the SQLite database first (so we have history on page load), then sanitize and broadcast it live via WebSockets.
    

**3\. UI/UX Design Rules**

*   The dashboard must use a strict **dark theme**. Do not generate light theme CSS.
    
*   The design language should be clean, minimalist, and highly responsive (aim for an Apple-like aesthetic with smooth scrolling and clean typography).
    

**Instructions:** Acknowledge these parameters, confirm you understand the architecture, and outline the 5 phases we will use to build this. Wait for my permission before writing the code for Phase 1.