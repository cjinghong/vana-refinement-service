import os
import tempfile
from urllib.parse import urlparse

import requests
import vana
import json

from refiner.errors.exceptions import FileDownloadError

def _extract_extension_from_content_disposition(headers):
    """Extract file extension from Content-Disposition header."""
    if 'Content-Disposition' not in headers:
        return None
    
    content_disposition = headers['Content-Disposition']
    if 'filename=' not in content_disposition:
        return None
    
    # Parse filename from Content-Disposition header
    filename_start = content_disposition.index('filename=') + 9
    filename_end = content_disposition.find(';', filename_start)
    if filename_end == -1:
        filename_end = len(content_disposition)
    
    filename = content_disposition[filename_start:filename_end].strip('"\'')
    _, ext = os.path.splitext(filename)
    return ext if ext else None


def _extract_extension_from_url_path(file_url):
    """Extract file extension from URL path."""
    parsed_url = urlparse(file_url)
    _, ext = os.path.splitext(parsed_url.path)
    return ext if ext else None


def _extract_extension_from_content_type(headers):
    """Extract file extension from Content-Type header."""
    if 'Content-Type' not in headers:
        return None
    
    content_type = headers['Content-Type'].lower().split(';')[0].strip()
    mime_to_ext = {
        'application/pdf': '.pdf',
        'application/zip': '.zip',
        'application/x-gzip': '.gz',
        'application/x-tar': '.tar',
        'application/x-compressed': '.zip',
        'application/x-7z-compressed': '.7z',
        'application/json': '.json',
        'text/csv': '.csv',
        'text/plain': '.txt',
        'image/jpeg': '.jpg',
        'image/png': '.png'
    }
    return mime_to_ext.get(content_type, None)


def download_file(file_url: str) -> str:
    """
    Downloads a file from a URL into a temporary directory.

    Args:
        file_url (str): URL of the file to download.

    Returns:
        str: Path to the downloaded file in a temporary location.
             The caller is responsible for cleaning up this file and its directory.

    Raises:
        FileDownloadError: If file download fails.
    """
    temp_dir = tempfile.mkdtemp()
    file_extension = None

    # Attempt to determine file extension
    try:
        response = requests.head(file_url, allow_redirects=True, timeout=10)
        response.raise_for_status()

        # Check Content-Disposition header first
        file_extension = _extract_extension_from_content_disposition(response.headers)
        
        # If no extension from header, try URL path
        if file_extension is None:
            file_extension = _extract_extension_from_url_path(file_url)

        # If still no extension, check Content-Type header
        if file_extension is None:
            file_extension = _extract_extension_from_content_type(response.headers)

    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors more granularly
        if hasattr(e.response, 'status_code'):
            status_code = e.response.status_code
            
            # These errors might be HEAD-specific, so continue with fallback and let GET attempt
            if status_code in (404, 405, 501):  # Not Found, Method Not Allowed, Not Implemented
                vana.logging.warning(f"HEAD request failed (HTTP {status_code}) for '{file_url}'. May be HEAD-specific issue. Continuing with URL path detection.")
                file_extension = _extract_extension_from_url_path(file_url)
            
            # Auth errors - might be different for HEAD vs GET, so try the download
            elif status_code in (401, 403):  # Unauthorized, Forbidden
                vana.logging.warning(f"HEAD request unauthorized (HTTP {status_code}) for '{file_url}'. Will attempt download anyway as GET might have different auth.")
                file_extension = _extract_extension_from_url_path(file_url)
            
            # Other 4xx/5xx errors - log and continue, let the actual download attempt decide
            else:
                vana.logging.warning(f"HEAD request failed (HTTP {status_code}) for '{file_url}': {e}. Continuing with fallback detection.")
                file_extension = _extract_extension_from_url_path(file_url)
        else:
            # HTTP error without status code - continue with fallback
            vana.logging.warning(f"HTTP error during extension detection for '{file_url}': {e}. Continuing with fallback detection.")
            file_extension = _extract_extension_from_url_path(file_url)
            
    except (requests.exceptions.RequestException, Exception) as e:
        # Network errors, timeouts, etc. - these don't necessarily mean the download will fail
        # so we log and continue with fallback extension detection
        vana.logging.debug(f"Could not determine file extension from headers for '{file_url}': {e}. Using URL path fallback.")
        file_extension = _extract_extension_from_url_path(file_url)

    # Set default extension if we still couldn't determine one
    if file_extension is None:
        file_extension = '.json'
        vana.logging.debug(f"Could not determine file extension for '{file_url}'. Using default: {file_extension}")

    encrypted_file_path = os.path.join(temp_dir, f"encrypted_file{file_extension}")

    # Download the actual file
    try:
        response = requests.get(file_url, stream=True, timeout=30)
        response.raise_for_status()
        with open(encrypted_file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        vana.logging.info(f"Successfully downloaded file to: {encrypted_file_path}")
        return encrypted_file_path
    except requests.exceptions.RequestException as e:
        # Clean up temp dir and file if download fails
        try:
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)
        except OSError:
            pass
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass
        raise FileDownloadError(file_url=file_url, error=str(e))


def detect_file_type(file_path):
    """
    Detect file type based on content analysis.
    
    Args:
        file_path (str): Path to the file to analyze
        
    Returns:
        str: Detected file extension with leading dot (e.g., '.json')
    """
    # Try using python-magic if available (most reliable)
    try:
        import magic
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_path)
        
        # Map common MIME types to extensions
        mime_to_ext = {
            'application/json': '.json',
            'application/zip': '.zip',
            'application/x-tar': '.tar',
            'application/gzip': '.gz',
            'application/x-gzip': '.gz',
            'application/x-bzip2': '.bz2',
            'application/x-xz': '.xz',
            'application/x-7z-compressed': '.7z',
            'text/plain': '.txt',
            'text/csv': '.csv',
            'text/html': '.html',
            'application/pdf': '.pdf',
            'image/jpeg': '.jpg',
            'image/png': '.png'
        }
        
        if mime_type in mime_to_ext:
            return mime_to_ext[mime_type]
        
        # For generic types, do more specific detection
        if mime_type == 'text/plain':
            # Check if it's JSON
            if is_json_file(file_path):
                return '.json'
            
    except ImportError:
        vana.logging.debug("python-magic not available, falling back to basic detection")
    
    # Basic detection without dependencies
    
    # Check if it's JSON
    if is_json_file(file_path):
        return '.json'
    
    # Check if it's text
    if is_text_file(file_path):
        return '.txt'
    
    # Check for archive signatures
    with open(file_path, 'rb') as f:
        header = f.read(8)  # Read first 8 bytes
        
        # ZIP files start with PK\x03\x04
        if header.startswith(b'PK\x03\x04'):
            return '.zip'
        
        # gzip files start with 1F 8B
        if header.startswith(b'\x1f\x8b'):
            return '.gz'
        
        # tar files can vary, but common ones start with "ustar" at position 257
        f.seek(257)
        if f.read(5) == b'ustar':
            return '.tar'
    
    # Default if no detection succeeds
    return os.path.splitext(file_path)[1] or '.bin'


def is_json_file(file_path):
    """Check if file contains valid JSON."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Check for JSON structures
            if (content.strip().startswith('{') and content.strip().endswith('}')) or \
               (content.strip().startswith('[') and content.strip().endswith(']')):
                json.loads(content)
                return True
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        pass
    return False


def is_text_file(file_path, sample_size=8192):
    """
    Check if file appears to be text by examining a sample.
    Binary files typically contain null bytes and many non-printable characters.
    """
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
            # Count null bytes and control characters
            null_count = sample.count(0)
            control_count = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))  # Tab, LF, CR are ok
            
            # If >30% are null or control chars, likely binary
            if (null_count + control_count) / len(sample) > 0.3:
                return False
            
            # Try to decode as utf-8
            try:
                sample.decode('utf-8')
                return True
            except UnicodeDecodeError:
                return False
    except:
        return False
