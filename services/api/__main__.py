"""Run the control plane: python -m services.api"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("services.api.app:app", host="0.0.0.0", port=8000, proxy_headers=False, log_level="info")
