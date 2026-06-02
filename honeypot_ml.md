I want to implement an unsupervised machine learning layer using scikit-learn (such as Isolation Forest for anomaly detection or DBSCAN for clustering) to analyze this threat data.

Please provide the following:

1.  **Feature Engineering:** A standalone Python script using pandas that reads the SQLite database and engineers numerical features (e.g., request velocity per IP, payload character length, and time-based metrics).
    
2.  **Model Training:** The code to train the unsupervised model offline on this extracted data and export it as a .pkl or .joblib file.
    
3.  **Live Inference:** The FastAPI code showing how to load this saved model into memory on server startup and use it inside the ASGI middleware to instantly score incoming requests without blocking the async event loop."