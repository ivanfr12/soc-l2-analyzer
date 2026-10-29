# SOC L2 Analyzer - Agent Instructions

## Project goal
Build a web application for the Comunidad Dojo SOC L2 challenge.
The application must analyze Excel security logs, correlate evidence,
present findings in a dashboard, and generate executive and technical PDF reports.

## Working rules
- Inspect the existing repository before modifying files.
- Preserve existing work and conventions.
- Work in small, reviewable stages. Do not build the entire application in one task.
- Explain the intended changes before making substantial modifications.
- Never delete or overwrite existing project files without explicit approval.
- Do not invent findings, fields, indicators, or evidence.
- Keep detection logic deterministic, testable, and separate from AI-generated explanations.
- Every finding must include supporting evidence and a traceable detection rule.
- Use AI only to explain structured findings; never let AI fabricate detection evidence.
- Handle malformed Excel files and missing columns gracefully.
- Keep secrets, API keys, environment files, and private datasets out of Git.
- Do not introduce Docker, a database, or paid services unless justified.
- Use local Ollama for AI integration when that stage is reached.
- Keep the application useful if Ollama is unavailable.
- Add automated tests for important behavior.
- Document Windows setup and execution commands.

## Proposed stack
- Frontend: React, Vite, TypeScript, Material UI, Recharts.
- Backend: Python, FastAPI, pandas, openpyxl.
- PDF generation: ReportLab.
- Local AI: Ollama, integrated behind a separate service.

## Initial task
Inspect the repository, its Git state, dependencies, and available project files.
Inspect the challenge workbook if available.
Do not implement the application yet.
Report findings, risks, architecture recommendations, and a prioritized backlog.
