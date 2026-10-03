# Privacy Policy for Anti-Phishing AI Guard

**Effective date:** October 3, 2026

This policy describes the current repository implementation. The operator should verify it against the deployed backend and hosting configuration before publishing it.

## Information processed

When protection is enabled, the extension sends the full HTTP or HTTPS URL to the configured analysis backend. A URL can contain sensitive information in its path or query string. The backend uses URL rules and a machine-learning model, submits the URL to PhishTank for lookup, and makes a limited request to the destination site to inspect selected HTML features. That request does not include the user's browser cookies and does not execute the page's JavaScript.

## Storage and retention

- **On the device:** The extension stores recent scan history, including the full URL, in browser storage. Users can clear the scan history from the extension. Settings and counters are also stored locally.
- **Backend logs:** URLs are logged with their query strings and fragments removed. The URL path is retained and could itself contain sensitive information.
- **Firebase, if configured:** Phishing/suspicious detections and user-submitted reports are stored with the sanitized URL, status/reason, timestamps, and counts. Query strings and fragments are removed, but URL paths are retained. The current code does not define an automatic deletion or retention period.

The project does not sell URL data. URL data is shared with the configured backend, PhishTank, the destination host for page retrieval, and service providers used to operate the backend (including Firebase and the configured host).

## User controls

Users can clear local scan history in the extension and can disable protection in settings. Disabling protection stops new analysis requests but does not delete previously stored backend records. To request deletion of server-side records, contact the project maintainer through the repository and include enough information to locate the record.

## Security and limitations

The extension and backend use security controls, including HTTPS for the configured production API and restrictions on server-side URL fetching. No security product can guarantee that every classification is correct. **Unable to verify** means the scan did not complete; it is neither a phishing verdict nor proof that the site is safe.

## Contact

For privacy questions or deletion requests, contact the project maintainer through the repository.
