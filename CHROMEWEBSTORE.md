# Chrome Web Store Draft — Anti-Phishing AI Guard v2.2.0

Use this as a factual draft only. Confirm the final data disclosures, store policy answers, listing assets, and privacy policy URL before submission.

## Store listing

**Name:** Anti-Phishing AI Guard
**Short name:** Anti-Phishing Guard
**Summary:** Checks web addresses before navigation and warns when a site is suspicious or could not be verified.

**Description:**

Anti-Phishing AI Guard checks HTTP and HTTPS destinations using a remote analysis service. The service combines URL rules, a legacy machine-learning model, a PhishTank lookup, and a limited server-side page fetch. The extension shows separate outcomes for phishing, suspicious, safe-with-no-detection, and unable-to-verify results.

An unable-to-verify result means the scan did not complete. It is not a phishing verdict and does not establish that a site is safe. Users can return to safety or choose to continue without a completed scan.

The extension stores recent scan history locally and offers an optional user-report action. Detection is imperfect; use normal care with links and credentials.

## Privacy and data flow

**Single purpose:** Check the URLs users visit for phishing indicators and show an appropriate warning or scan status.

**Data processed:** The full URL is sent from the extension to the configured backend. URLs can contain sensitive information in their paths or query strings; users should avoid navigating to URLs containing private tokens while scanning is enabled.

**Third-party processing:** The backend submits the URL to PhishTank for lookup and makes a limited HTTP(S) request to the destination to inspect selected page features. It does not use the user's browser cookies or execute the destination's JavaScript.

**Storage and retention:** The extension stores the most recent scan history, including full URLs, locally in browser storage; users can clear scan history in the extension. When Firebase is configured, phishing/suspicious detections and user-submitted reports are stored server-side. The stored URL omits query strings and fragments, but retains the path; detection records also retain status, confidence, timestamps, and counts. The application does not currently implement an automatic retention period for those Firebase records.

**Sharing and sale:** The project does not sell URL data. URL data is shared with the configured backend, PhishTank, and the destination host as described above. Firebase and the backend hosting provider process data for service operation.

## Permission notes to verify

- `webNavigation`, `tabs`, and HTTP/HTTPS host permissions support intercepting and analyzing navigations.
- `storage` keeps local preferences and recent scan history.
- `notifications` displays threat notifications.
- `activeTab` is declared in the manifest; verify that the shipped code needs it and remove it if it is unused.

## Before submission

- Publish a privacy policy matching the data flow and retention statements above.
- Verify every Chrome Web Store privacy-practices answer against the shipped code and production backend configuration.
- Confirm backend availability, production configuration, and model limitations.
- Prepare store screenshots and promotional assets required by the dashboard.
- Package only the contents of `extension/`; do not include the backend, datasets, credentials, `.git`, or development/test files.
- Test the ZIP by loading it as an unpacked extension before upload.
