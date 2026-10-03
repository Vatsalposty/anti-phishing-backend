# Privacy Summary — Anti-Phishing AI Guard

The extension checks HTTP and HTTPS URLs using the configured backend. A scan can send the full URL to that backend, and the backend may send it to PhishTank for a threat lookup and request the destination page for limited HTML analysis. The destination request does not use browser cookies or execute page JavaScript.

URLs may contain sensitive data in their paths or query strings. Query strings and fragments are removed from server logs and Firebase records, but paths are retained. When Firebase is configured, phishing/suspicious detections and user-submitted reports may be stored with status, timestamps, and counts. The service does not currently apply an automatic retention period to these records.

The extension stores recent scan history, including full URLs, and settings locally in browser storage. Users can clear the scan history in the extension. URLs are shared with the configured backend, PhishTank, and the destination host as required for scanning. The project does not sell URL data.

This project does not guarantee that a site is safe or malicious. An unable-to-verify result means the scan did not complete.

For questions or data deletion requests, contact the project maintainer through the repository.
