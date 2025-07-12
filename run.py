#!/usr/bin/env python3
"""
Entry point script for HSM Edwards API.
This script can be used to run the application in development or production.
"""

import sys
import os
import argparse
import uvicorn

# Add the project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def run_development():
    """Run the application in development mode with auto-reload."""
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=[project_root],
        log_level="info"
    )

def run_production():
    """Run the application in production mode."""
    from app.config import settings
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        workers=settings.WORKER_COUNT,
        worker_class="uvicorn.workers.UvicornWorker",
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True
    )

def main():
    parser = argparse.ArgumentParser(description="HSM Edwards API Server")
    parser.add_argument(
        "--mode",
        choices=["dev", "prod"],
        default="dev",
        help="Run mode: dev (development with auto-reload) or prod (production)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)"
    )
    
    args = parser.parse_args()
    
    # Check if .env file exists
    env_file = os.path.join(project_root, ".env")
    if not os.path.exists(env_file):
        print("⚠️  Warning: .env file not found!")
        print("📋 Please copy environment.template to .env and configure your environment variables:")
        print("   cp environment.template .env")
        print("")
        return 1
    
    print(f"🚀 Starting HSM Edwards API in {args.mode} mode...")
    print(f"🌐 Server will be available at http://{args.host}:{args.port}")
    print(f"📚 API documentation will be available at http://{args.host}:{args.port}/api/v1/docs")
    print("")
    
    try:
        if args.mode == "dev":
            uvicorn.run(
                "app.main:app",
                host=args.host,
                port=args.port,
                reload=True,
                reload_dirs=[project_root],
                log_level="info"
            )
        else:
            # For production, import settings to validate configuration
            from app.config import settings
            uvicorn.run(
                "app.main:app",
                host=args.host,
                port=args.port,
                workers=settings.WORKER_COUNT,
                log_level=settings.LOG_LEVEL.lower(),
                access_log=True
            )
    except KeyboardInterrupt:
        print("\n👋 Shutting down HSM Edwards API...")
        return 0
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 