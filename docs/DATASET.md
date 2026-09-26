# Clinical dataset

The project uses the UCI Machine Learning Repository's **Diabetes 130-US Hospitals for Years 1999-2008** collection (dataset 296). It contains 101,766 inpatient encounter rows from 130 US hospitals, with 47 data features. UCI publicly releases it under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.

Dataset attribution:

> Clore, J., Cios, K., DeShazo, J., & Strack, B. (2014). *Diabetes 130-US Hospitals for Years 1999-2008* [Dataset]. UCI Machine Learning Repository. https://doi.org/10.24432/C5230J.

## Download

Run `python -m resilience.cli dataset fetch`. The loader downloads from the official UCI host, checks the ZIP CRC and required CSV schema, confirms the expected encounter row count, and writes the source files plus attribution and SHA-256 hashes to `data/raw/` inside this project.

UCI flags the data as potentially sensitive: it includes age, gender, race, encounter IDs and patient numbers. The raw records are ignored by version control. Do not commit or publish `data/raw/`, post record screenshots, or use the records for clinical decisions. The dashboard should display aggregate counts only. The data is historical and is for systems demonstration.

MIMIC-IV is larger, but its files require a credentialed account, training, identity verification and an accepted data-use agreement; this project will not try to bypass those controls.
