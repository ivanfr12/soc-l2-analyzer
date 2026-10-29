# SOC L2 Analyzer - Project Plan

## Objective
Create a web application that analyzes the challenge Excel logs,
correlates events, presents evidence-backed findings, and generates
executive and technical PDF reports.

## Phase 1 - Repository and data assessment
- Inspect existing files and Git state.
- Inspect the workbook schema, data quality, timestamps, and event types.
- Confirm the official challenge requirements.
- Record risks and acceptance criteria.

## Phase 2 - Detection engine
- Implement Excel validation and parsing.
- Create deterministic detection rules.
- Correlate events into incidents.
- Attach evidence, timestamps, affected entities, and severity.
- Add automated tests.

## Phase 3 - API
- Expose upload and analysis endpoints.
- Return structured findings and summary metrics.
- Validate input and handle errors.

## Phase 4 - Dashboard
- Display summary metrics and severity counts.
- List and filter incidents.
- Show timelines and supporting events.

## Phase 5 - Reports
- Generate an executive report in Spanish.
- Generate a technical report with detailed evidence.
- Test consistency with dashboard results.

## Phase 6 - Local AI
- Integrate Ollama behind an optional service.
- Use structured findings as context.
- Clearly separate evidence from generated explanations.
- Provide a fallback when the model is unavailable.

## Phase 7 - Validation and delivery
- Run end-to-end tests using the challenge workbook.
- Document Windows setup and usage.
- Publish the repository.
- Record and verify the demonstration video and submission links.

## Acceptance criteria
- Invalid Excel files produce understandable errors.
- Findings can be traced to source log records.
- Detection rules are reproducible and tested.
- Both PDFs are generated successfully.
- The dashboard and reports use consistent analysis results.
- The core analysis works without an AI model.
