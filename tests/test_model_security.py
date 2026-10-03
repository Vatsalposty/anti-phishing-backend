import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import socket

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))
from model import PhishingModel, secure_fetch
from firebase_db import sanitize_url

class TestModelSecurity(unittest.TestCase):
    def setUp(self):
        self.model = PhishingModel()
        # Keep model tests fully offline; prediction otherwise queries the
        # external PhishTank service before reaching the mocked HTML fetch.
        phishtank_patch = patch.object(self.model, 'check_phishtank', return_value=None)
        phishtank_patch.start()
        self.addCleanup(phishtank_patch.stop)

    def test_sanitize_url_removes_userinfo_query_and_fragment(self):
        self.assertEqual(
            sanitize_url('https://alice:secret@example.com/reset/token?email=a%40b.test#fragment'),
            'https://example.com/reset/token'
        )

    @patch('socket.getaddrinfo')
    def test_direct_private_ip(self, mock_dns):
        # Mock DNS resolving to private IP
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 80))]

        with self.assertRaisesRegex(ValueError, "Blocked internal/private IP: 10.0.0.1"):
            secure_fetch("http://example.com")

        features = self.model.analyze_html_content("http://example.com")
        self.assertFalse(features['fetched'])

    @patch('socket.getaddrinfo')
    @patch('socket.create_connection')
    def test_mixed_public_private_dns_private_first(self, mock_conn, mock_dns):
        # Mock DNS returning a private IP first
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))
        ]

        with self.assertRaisesRegex(ValueError, "Blocked internal/private IP"):
            secure_fetch("http://example.com")

    @patch('socket.getaddrinfo')
    @patch('socket.create_connection')
    def test_mixed_public_private_dns_public_first(self, mock_conn, mock_dns):
        # Mock DNS returning a public IP first, then private
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 80))
        ]

        with self.assertRaisesRegex(ValueError, "Blocked internal/private IP"):
            secure_fetch("http://example.com")

    @patch('socket.getaddrinfo')
    def test_ipv6_private(self, mock_dns):
        # Mock DNS returning IPv6 loopback
        mock_dns.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 80, 0, 0))]

        with self.assertRaisesRegex(ValueError, "Blocked internal/private IP: ::1"):
            secure_fetch("http://example.com")

    @patch('socket.getaddrinfo')
    @patch('socket.create_connection')
    @patch('http.client.HTTPConnection')
    def test_redirect_to_private(self, mock_http, mock_conn, mock_dns):
        def dns_side_effect(host, *args, **kwargs):
            if host == "example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]
            else:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]

        mock_dns.side_effect = dns_side_effect

        mock_conn_instance = MagicMock()
        mock_conn.return_value = mock_conn_instance

        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance

        mock_response = MagicMock()
        mock_response.status = 302
        mock_response.getheader.return_value = "http://127.0.0.1/"
        mock_http_instance.getresponse.return_value = mock_response

        with self.assertRaisesRegex(ValueError, "Blocked internal/private IP: 127.0.0.1"):
            secure_fetch("http://example.com")

    @patch('socket.getaddrinfo')
    @patch('socket.create_connection')
    @patch('http.client.HTTPConnection')
    def test_too_many_redirects(self, mock_http, mock_conn, mock_dns):
        # We simulate a chain of 4 redirects. By default max_redirects is 3.
        # This means the 4th request (or hitting the 4th redirect) should raise "Too many redirects".
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]

        mock_conn_instance = MagicMock()
        mock_conn.return_value = mock_conn_instance

        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance

        mock_response = MagicMock()
        mock_response.status = 302
        mock_response.getheader.return_value = "http://example.com/redirect"
        mock_http_instance.getresponse.return_value = mock_response

        with self.assertRaisesRegex(ValueError, "Too many redirects"):
            secure_fetch("http://example.com", max_redirects=3)

    def test_invalid_scheme(self):
        with self.assertRaisesRegex(ValueError, "Invalid scheme: ftp"):
            secure_fetch("ftp://example.com")

    def test_invalid_port(self):
        with self.assertRaisesRegex(ValueError, "Blocked scheme/port combination: http:8080"):
            secure_fetch("http://example.com:8080")

    @patch('socket.getaddrinfo')
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_invalid_tls(self, mock_ssl, mock_conn, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]

        mock_context = MagicMock()
        mock_context.wrap_socket.side_effect = Exception("CERTIFICATE_VERIFY_FAILED")
        mock_ssl.return_value = mock_context

        with self.assertRaisesRegex(Exception, "CERTIFICATE_VERIFY_FAILED"):
            secure_fetch("https://example.com")

    @patch('socket.getaddrinfo')
    def test_dns_failure(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("Name or service not known")

        with self.assertRaisesRegex(ValueError, "DNS resolution failed"):
            secure_fetch("http://nonexistent.domain")

        status, conf, reason = self.model.predict("http://nonexistent.domain")
        self.assertEqual(status, 'unable_to_verify')
        self.assertEqual(reason, 'Unreachable Destination')

    @patch('socket.getaddrinfo')
    @patch('socket.create_connection')
    @patch('http.client.HTTPConnection')
    def test_response_size_limits(self, mock_http, mock_conn, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]

        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance

        mock_response = MagicMock()
        mock_response.status = 200

        def read_side_effect(size):
            return b"A" * size

        mock_response.read.side_effect = read_side_effect
        mock_http_instance.getresponse.return_value = mock_response

        content = secure_fetch("http://example.com", max_bytes=1024)

        self.assertEqual(len(content), 1024)

if __name__ == '__main__':
    unittest.main()
