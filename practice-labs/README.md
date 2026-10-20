# Practical Investigation Labs

RootGuard labs are self-contained exercises designed for defensive analysts. No production account or tenant is needed for the synthetic-data exercises.

## Labs

1. [Lab 01: Investigating password-spray patterns](password-spray-investigation.md) — analyse synthetic Entra-style sign-in events, distinguish widespread failures from a follow-on successful authentication, and document evidential limitations.

## Working method

Read the scenario, execute the self-contained KQL using a compatible Kusto environment, compare results with expected observations, and document your hypothesis, supporting facts, alternative explanations and escalation criteria. Queries over synthetic events demonstrate analytic logic but **do not validate an operational detection in a real tenant**.

All lab data are fictional. Do not execute authentication attacks against live systems.
