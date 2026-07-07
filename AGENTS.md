# Agent Instructions for Sentinel-X

## Tools & Conventions

### Available Tools
- `bash` - Execute shell commands (PowerShell on Windows, bash on Linux/Mac)
- `edit` - Make targeted string replacements in files (prefer over full rewrites)
- `glob` - Fast file pattern matching (e.g., `**/*.py`, `src/**/*.ts`)
- `grep` - Search file contents with regex
- `read` - Read files or directories
- `write` - Write new files (must read existing files first before editing)
- `webfetch` - Fetch URL content
- `websearch` - Search the web

### Code Style Guidelines

1. **No comments** - Do NOT add comments to code unless absolutely necessary
2. **Conciseness** - Be concise, direct, and to the point in responses and code
3. **Convention-aware** - Read surrounding code before making changes to understand patterns
4. **Libraries** - Check existing dependencies before using new libraries

### File Operations
- Prefer `edit` for modifications to existing files
- Use `write` only for new files or complete rewrites
- Always `read` a file before editing it
- Never create documentation files (*.md) or README files unless explicitly requested

### Project-Specific Conventions

#### Backend (Python/FastAPI)
- Python 3.11+, FastAPI, SQLAlchemy async, Pydantic v2
- Alembic for migrations
- Project structure under `backend/app/`:
  - `agents/` - AI Agent implementations (LangGraph, CrewAI)
  - `api/` - REST API route handlers
  - `core/` - Config, database sessions, security
  - `digital_twin/` - Digital Twin simulation engine
  - `knowledge_graph/` - Neo4j integration
  - `ml/` - ML model training/prediction code
  - `models/` - SQLAlchemy ORM models
  - `schemas/` - Pydantic request/response schemas
  - `services/` - Business logic layer
  - `utils/` - Helper functions (MITRE mapping, CVSS scoring)

#### Frontend (Next.js/TypeScript)
- Next.js 14 App Router, TypeScript strict
- TailwindCSS for styling, `class-variance-authority` + `tailwind-merge` for variants
- `lucide-react` for icons
- `reactflow` for graph visualization
- `recharts` for charts
- Three.js / @react-three/fiber for 3D visualizations
- Radix UI primitives for accessible components

#### Database Connections
- PostgreSQL via SQLAlchemy async with asyncpg driver
- Neo4j via neo4j Python driver (bolt protocol)
- Qdrant via qdrant-client
- Redis via redis-py

#### AI/ML Stack
- LangGraph for agent orchestration
- CrewAI for multi-agent coordination
- Ollama with Llama 3.1 for local LLM inference
- sentence-transformers for embeddings
- scikit-learn (Isolation Forest) for anomaly detection
- PyTorch for deep learning models (Autoencoder, LSTM)
- NetworkX for graph algorithms

### Environment Variables
- All configuration via environment variables (see `.env.example`)
- Never hardcode secrets or credentials
- Use `pydantic-settings` for backend config management

### Git Workflow
- Only commit when explicitly asked
- Before committing: check `git status`, `git diff`, `git log --oneline -10`
- Write concise commit messages matching repo style
- Never force push, skip hooks, or amend unless explicitly requested

### Testing
- Backend tests in `backend/tests/`
- Frontend tests if present
- Run lint/typecheck before considering task complete

### Security
- Never log or expose secrets/keys
- Never commit secrets to repository
- Follow least privilege principle
- Validate all inputs
