"""Compatibility launcher. K4 v24 uses one port only: 8000/admin."""
import uvicorn

if __name__ == "__main__":
    print("K4 v24 uses a single server. Open http://127.0.0.1:8000/admin")
    uvicorn.run("phishhunter.asgi:app", host="127.0.0.1", port=8000, reload=True)
