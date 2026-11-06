"""The only code here that opens an outside connection. HTTPS, listed hosts only, no redirects off
the list, a size cap, and a timeout. It never follows a URL taken from an event or a provider."""
import email.utils
import time
import urllib.error
import urllib.parse
import urllib.request


class WebError(Exception):
    def __init__(self, message, status=None, retry_after=None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class _ListedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, request, fp, code, message, headers, new_url):
        check(new_url, self.hosts)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def check(url, hosts):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https':
        raise WebError(f'refused: not HTTPS: {parts.hostname}')
    if parts.hostname not in hosts:
        raise WebError(f'refused: host is not listed: {parts.hostname}')
    if parts.username or parts.password:
        raise WebError('refused: URL holds credentials')


def retry_after(headers):
    value = headers.get('Retry-After') if headers else None
    if not value:
        return None
    if value.isdigit():
        return int(value)
    parsed = email.utils.parsedate_to_datetime(value)
    return max(int(parsed.timestamp() - time.time()), 0) if parsed else None


class Web:
    def __init__(self, hosts, timeout=15, opener=None):
        self.hosts = frozenset(hosts)
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener(_ListedRedirects(self.hosts)).open

    def fetch(self, url, headers=None, data=None, max_bytes=2097152, method=None):
        """Returns (status, headers, body). Keys travel in headers, never in the URL. A 304 is a result."""
        check(url, self.hosts)
        request = urllib.request.Request(url, data=data, headers={'User-Agent': 'siem-enricher/1', **(headers or {})}, method=method)
        try:
            with self.opener(request, timeout=self.timeout) as response:
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise WebError(f'response over {max_bytes} bytes')
                return response.status, response.headers, body
        except urllib.error.HTTPError as error:
            if error.code == 304:
                return 304, error.headers, b''
            if error.code == 404:
                return 404, error.headers, b''
            raise WebError(f'HTTP {error.code}', error.code, retry_after(error.headers)) from None
        except urllib.error.URLError as error:
            reason = getattr(error, 'reason', error)
            raise WebError(f'{type(reason).__name__}') from None
        except OSError as error:
            raise WebError(f'{type(error).__name__}') from None
