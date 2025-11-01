"""
Web Crawler Scraper
Main scraper module with comprehensive trap detection and report generation
"""

import re
import json
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs
from bs4 import BeautifulSoup
import configparser
from collections import defaultdict, Counter

# ============================================================================
# GLOBAL STATE FOR REPORT TRACKING
# ============================================================================

unique_urls = set()  # Unique URLs crawled
url_to_word_count = {}  # Word count per URL
all_words = []  # All words from all pages for frequency analysis
longest_page_url = ""
longest_page_count = 0
subdomain_urls = defaultdict(set)  # Store unique URLs per subdomain

# Similarity detection tracking
url_to_word_vector = {}  # Store word vectors (TF-IDF) per URL
document_frequencies = defaultdict(int)  # Track how many docs contain each word
total_documents = 0
exact_content_hashes = set()  # Store exact content hashes for duplicate detection

# Stopwords for filtering
STOPWORDS = {
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
    'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
    'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
    'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
    'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go',
    'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
    'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them',
    'see', 'other', 'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over',
    'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first',
    'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day',
    'most', 'us', 'are', 'had', 'been', 'were', 'being', 'have', 'has', 'had'
}

# ============================================================================
# CONFIGURATION FUNCTIONS
# ============================================================================

def get_allowed_domains():
    """
    Load allowed domains from config.ini file
    """
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    # Get seed URLs from config
    seed_urls = config["CRAWLER"]["SEEDURL"].split(",")
    
    # Extract base domains from seed URLs (remove www. prefix for subdomain matching)
    allowed_domains = []
    for url in seed_urls:
        url = url.strip()
        if url:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain:
                # Remove www. prefix to allow subdomain matching
                if domain.startswith('www.'):
                    domain = domain[4:]  # Remove 'www.'
                if domain and domain not in allowed_domains:
                    allowed_domains.append(domain)
    
    return allowed_domains

# ============================================================================
# TRAP DETECTION FUNCTIONS
# ============================================================================

def is_infinite_trap(url):
    """
    Detect infinite traps (URLs that lead to infinite loops)
    """
    try:
        parsed = urlparse(url)
        
        # Check for session IDs and dynamic parameters that change
        query_params_list = parse_qs(parsed.query)
        for param, values in query_params_list.items():
            param_lower = param.lower()
            # Session-like parameters
            if any(session_word in param_lower for session_word in 
                   ['session', 'sid', 'jsessionid', 'phpsessid', 'aspsessionid']):
                return True
            
            # Dynamic content parameters
            if any(dynamic_word in param_lower for dynamic_word in 
                   ['timestamp', 'time', 'random', 'cache', 'nocache', 'refresh']):
                return True
        
        # Check for excessive query parameters (potential trap)
        if len(query_params_list) > 5:
            return True
        
        # Check for URL patterns that might be traps
        path = parsed.path.lower()
        
        # Calendar/date-based traps
        if re.search(r'/(\d{4})/(\d{1,2})/(\d{1,2})', path):
            return True
        
        # Pagination traps (excessive page numbers)
        if re.search(r'/page/\d{3,}', path):
            return True
        
        # Search result traps
        if '/search' in path and len(query_params_list) > 3:
            return True
        
        # Check for excessive path depth
        path_parts = [p for p in path.split('/') if p]
        if len(path_parts) > 6:  # Too deep
            return True
        
        # Check for suspicious file extensions in path
        suspicious_extensions = ['.php', '.asp', '.jsp', '.cgi']
        if any(path.endswith(ext) for ext in suspicious_extensions):
            return True
        
        # Check for URL shorteners or redirects
        redirect_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if parsed.netloc.lower() in redirect_domains:
            return True
        
        # Check for admin/private areas
        private_paths = ['/admin', '/private', '/internal', '/secure', '/login', '/logout']
        if any(private_path in path for private_path in private_paths):
            return True
        
        return False
        
    except Exception as e:
        print(f"Error checking infinite trap for {url}: {e}")
        return False

# ============================================================================
# CONTENT QUALITY DETECTION FUNCTIONS
# ============================================================================

def is_dead_url(resp):
    """
    Detect dead URLs that return 200 but no useful data
    """
    try:
        if resp.status != 200:
            return True
        
        if not resp.raw_response or not resp.raw_response.content:
            return True
        
        content = resp.raw_response.content
        
        # Check for very small content
        if len(content) < 100:  # Less than 100 bytes
            return True
        
        # Check for error pages that return 200
        content_str = content.decode('utf-8', errors='ignore').lower()
        error_indicators = [
            'page not found', '404', 'not found', 'error', 'oops',
            'something went wrong', 'access denied', 'forbidden'
        ]
        
        if any(indicator in content_str for indicator in error_indicators):
            return True
        
        return False
        
    except Exception as e:
        print(f"Error checking dead URL: {e}")
        return True

def is_large_file_with_low_value(url, content):
    """
    Detect very large files with low information value
    """
    try:
        if not content:
            return False
        
        content_size = len(content)
        
        # Check file size (larger than 1MB)
        if content_size > 1024 * 1024:  # 1MB
            # Check if it's a binary file or has low text content
            try:
                content_str = content.decode('utf-8', errors='ignore')
                text_ratio = len(content_str) / content_size
                
                # If less than 10% is readable text, it's likely a binary file
                if text_ratio < 0.1:
                    return True
                    
            except:
                return True
        
        # Check for very large HTML files (more than 500KB)
        if content_size > 500 * 1024:  # 500KB
            soup = BeautifulSoup(content, "html.parser")
            text_content = soup.get_text()
            
            # If text content is less than 20% of total size, low value
            if len(text_content) / content_size < 0.2:
                return True
        
        return False
        
    except Exception as e:
        print(f"Error checking large file for {url}: {e}")
        return False

def has_high_textual_content(content):
    """
    Check if page has high textual information content
    Combines low info detection and high quality checks
    """
    try:
        if not content:
            return False
        
        soup = BeautifulSoup(content, "html.parser")
        
        # Remove non-content elements
        for script in soup(["script", "style", "nav", "header", "footer"]):
            script.decompose()
        
        # Get text content
        text_content = soup.get_text()
        
        # Check for minimum text content (< 200 chars is low info)
        if len(text_content.strip()) < 200:
            return False
        
        # Simple word count check (words of 3+ characters)
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text_content.lower())
        if len(words) < 100:  # Need at least 100 words
            return False
        
        # Look for content-rich elements
        content_elements = soup.find_all(['article', 'main', 'div', 'section', 'p'])
        if len(content_elements) < 3:  # Need at least some structure
            return False
        
        return True
        
    except Exception as e:
        print(f"Error checking textual content: {e}")
        return False

# ============================================================================
# TEXT PROCESSING FUNCTIONS
# ============================================================================

def extract_words_from_text(text):
    """
    Extract words from text, filtering stopwords
    """
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    return [w for w in words if w not in STOPWORDS]

# ============================================================================
# SIMILARITY DETECTION FUNCTIONS (FROM SCRATCH - NO LIBRARIES)
# ============================================================================

def cosine_similarity(vec1, vec2):
    """
    Compute cosine similarity between two vectors
    cosine = (A · B) / (||A|| * ||B||)
    
    Implemented from scratch without any libraries (pure Python math)
    """
    # Get dot product (A · B)
    dot_product = 0.0
    for word in vec1:
        if word in vec2:
            dot_product += vec1[word] * vec2[word]
    
    # Compute magnitudes ||A|| and ||B||
    magnitude1 = sum(val ** 2 for val in vec1.values()) ** 0.5
    magnitude2 = sum(val ** 2 for val in vec2.values()) ** 0.5
    
    # Avoid division by zero
    if magnitude1 == 0 or magnitude2 == 0:
        return 0.0
    
    # Cosine similarity
    return dot_product / (magnitude1 * magnitude2)

def check_exact_similarity(content):
    """
    Check for exact duplicate content using hash
    
    Methodology:
    1. Extract text content from HTML
    2. Remove HTML markup, scripts, styles, navigation
    3. Create hash of the cleaned text
    4. Compare with previously seen hashes
    
    Returns True if exact duplicate found
    """
    global exact_content_hashes
    
    try:
        soup = BeautifulSoup(content, "html.parser")
        
        # Remove all non-content elements
        for script in soup(["script", "style", "nav", "header", "footer", "iframe", "noscript"]):
            script.decompose()
        
        # Get clean text content
        text_content = soup.get_text().strip().lower()
        
        # Create hash of the text
        content_hash = hash(text_content)
        
        # Check if we've seen this exact content before
        if content_hash in exact_content_hashes:
            return True
        
        # Add to seen hashes
        exact_content_hashes.add(content_hash)
        
        return False
        
    except Exception as e:
        print(f"Error checking exact similarity: {e}")
        return False

def compute_tf(word_counts):
    """
    Compute Term Frequency (TF) vector from word counts
    TF = count(word) / total_words
    
    This normalizes word counts by total words in document
    """
    total_words = sum(word_counts.values())
    if total_words == 0:
        return {}
    return {word: count / total_words for word, count in word_counts.items()}

def compute_idf(word, total_docs, doc_freq):
    """
    Compute Inverse Document Frequency (IDF)
    IDF = log(total_documents / document_frequency)
    
    Uses natural log for computational efficiency
    """
    import math
    if doc_freq == 0:
        return 0.0
    # Standard IDF formula: log(N / df)
    idf_ratio = total_docs / doc_freq
    # Use log base e for computation
    return math.log(idf_ratio)

def compute_tfidf_vector(word_counts):
    """
    Compute TF-IDF vector for a document
    TF-IDF = TF * IDF
    
    Combines Term Frequency with Inverse Document Frequency
    to weight important words higher
    """
    global total_documents, document_frequencies
    
    # Compute TF first
    tf_vector = compute_tf(word_counts)
    tfidf_vector = {}
    
    for word, tf_value in tf_vector.items():
        # Get IDF for this word based on how many documents contain it
        doc_freq = document_frequencies.get(word, 0)
        idf_value = compute_idf(word, total_documents, doc_freq) if doc_freq > 0 else 0.0
        
        # TF-IDF = TF * IDF
        tfidf_vector[word] = tf_value * idf_value
    
    return tfidf_vector

def check_near_similarity(url, word_counts):
    """
    Check for near-duplicate pages using TF-IDF and cosine similarity
    
    Methodology:
    1. Compute TF-IDF vector for current document
    2. Compare with all previous documents using cosine similarity
    3. If similarity > 90%, mark as near-duplicate
    
    Returns True if this page is similar (>90% cosine similarity) to any previously crawled page
    """
    global url_to_word_vector, total_documents, document_frequencies
    
    try:
        # Compute TF-IDF vector for THIS document BEFORE updating frequencies
        tfidf_vector = compute_tfidf_vector(word_counts)
        
        # Check cosine similarity with all previous documents
        for existing_url, existing_vector in url_to_word_vector.items():
            if existing_url == url:  # Skip itself
                continue
            
            # Compute cosine similarity between vectors
            similarity = cosine_similarity(tfidf_vector, existing_vector)
            
            # If similarity > 90%, consider it a near-duplicate
            if similarity > 0.90:
                print(f" Near-duplicate detected (similarity: {similarity:.2%}): {url}")
                return True
        
        # If not a duplicate, add this document to tracking
        # Update document frequencies for future comparisons
        unique_words = set(word_counts.keys())
        for word in unique_words:
            document_frequencies[word] += 1
        total_documents += 1
        
        # Store the TF-IDF vector for future comparisons
        url_to_word_vector[url] = tfidf_vector
        
        return False
        
    except Exception as e:
        print(f"Error checking near similarity: {e}")
        return False

# ============================================================================
# REPORT FUNCTIONS
# ============================================================================

def update_report(url, content):
    """
    Update report tracking with new URL and content
    """
    global unique_urls, url_to_word_count, longest_page_url, longest_page_count, subdomain_urls, all_words
    
    # Add to unique URLs
    unique_urls.add(url)
    
    # Extract and count words
    try:
        soup = BeautifulSoup(content, "html.parser")
        for script in soup(["script", "style", "nav", "header", "footer"]):
            script.decompose()
        text_content = soup.get_text()
        words = extract_words_from_text(text_content)
        word_count = len(words)
        
        # Track word count
        url_to_word_count[url] = word_count
        
        # Update longest page
        if word_count > longest_page_count:
            longest_page_url = url
            longest_page_count = word_count
        
        # Add words to global list (for frequency analysis)
        all_words.extend(words)
        
        # Track subdomain - add this URL to subdomain's set
        parsed = urlparse(url)
        subdomain = parsed.netloc.lower()
        subdomain_urls[subdomain].add(url)
        
    except Exception:
        pass  # Silently fail if extraction fails
    
    # Save report periodically (every 50 URLs)
    if len(unique_urls) % 50 == 0:
        save_report_json()

def has_similar_content(url, content):
    """
    Check if page has similar content to already crawled pages
    Uses both exact and near-similarity detection
    
    Returns True if page should be rejected due to similarity
    """
    global url_to_word_vector, document_frequencies, total_documents
    
    try:
        # First check for EXACT duplicates using hash
        if check_exact_similarity(content):
            print(f" Exact duplicate detected (hash): {url}")
            return True
        
        # Then check for NEAR-duplicates using TF-IDF + cosine similarity
        soup = BeautifulSoup(content, "html.parser")
        for script in soup(["script", "style", "nav", "header", "footer"]):
            script.decompose()
        text_content = soup.get_text()
        words = extract_words_from_text(text_content)
        
        # Create word count dictionary for TF-IDF
        word_counts = Counter(words)
        
        # Check near similarity using TF-IDF + cosine similarity
        if check_near_similarity(url, word_counts):
            print(f" Near-duplicate detected (TF-IDF + cosine): {url}")
            return True
        
        return False
        
    except Exception as e:
        print(f"Error checking similar content: {e}")
        return False

def save_report_json(filename="crawl_report.json"):
    """
    Save current report data to JSON file
    """
    global unique_urls, url_to_word_count, longest_page_url, longest_page_count, subdomain_urls, all_words
    
    # Get top 50 most common words
    word_freq = Counter(all_words)
    top_50_words = [(word, count) for word, count in word_freq.most_common(50)]
    
    # Get subdomains in alphabetical order with counts
    subdomain_list = [(subdomain, len(urls)) for subdomain, urls in sorted(subdomain_urls.items())]
    
    report = {
        "unique_pages_count": len(unique_urls),
        "longest_page": {
            "url": longest_page_url,
            "word_count": longest_page_count
        },
        "top_50_words": top_50_words,
        "subdomains": subdomain_list
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
    except Exception as e:
        print(f"Error saving report: {e}")

# ============================================================================
# MAIN SCRAPER FUNCTIONS
# ============================================================================

def scraper(url, resp):
    """
    Main scraper function with comprehensive trap detection and content analysis
    """
    try:
        # Check if response is valid
        if resp.status != 200:
            return []
        
        # Check for dead URLs
        if is_dead_url(resp):
            print(f" Dead URL detected: {url}")
            return []
        
        # Get content for analysis
        content = resp.raw_response.content if resp.raw_response else None
        
        # Check for large files with low value
        if is_large_file_with_low_value(url, content):
            print(f" Large file with low value detected: {url}")
            return []
        
        # Check for high textual content (only crawl pages with good content)
        if not has_high_textual_content(content):
            print(f" Low textual content detected: {url}")
            return []
        
        # Check for similar content (exact and near-duplicates using TF-IDF + cosine similarity)
        if has_similar_content(url, content):
            return []
        
        # Update report tracking with this URL
        update_report(url, content)
        
        # Extract links from the page
        links = extract_next_links(url, resp)
        valid_links = []
        
        for link in links:
            # Check if URL is valid (domain, file extensions, etc.)
            if not is_valid(link):
                continue
            
            # Check for infinite traps
            if is_infinite_trap(link):
                continue
            
            valid_links.append(link)
        
        return valid_links
        
    except Exception as e:
        print(f" Error in scraper for {url}: {e}")
        return []

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    links = []
    
    # Check if response is valid
    if resp.status != 200 or resp.raw_response is None or resp.raw_response.content is None:
        return links
    
    try:
        # Parse HTML content
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        
        # Find all anchor tags with href attributes
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            
            # Skip non-web links
            if href.startswith(("mailto:", "javascript:", "tel:")):
                continue
            
            # Convert relative URLs to absolute URLs
            abs_url = urljoin(resp.url, href)
            
            # Remove fragment part (everything after #)
            abs_url, _ = urldefrag(abs_url)
            
            links.append(abs_url)
            
    except Exception as e:
        print(f"Error extracting links from {url}: {e}")
        return links
    
    # Remove duplicates while preserving order
    return list(dict.fromkeys(links))

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        # Check if URL is within allowed domains from config.ini
        allowed_domains = get_allowed_domains()
        
        domain = parsed.netloc.lower()
        if not any(domain.endswith(d) for d in allowed_domains):
            return False
        
        # Check for unwanted file extensions
        path = parsed.path.lower()
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", path):
            return False
        
        # Check for unwanted paths
        if any(s in path for s in ["/calendar", "/feed", "/tag/"]):
            return False
        
        # Check for known crawler traps from community
        if any(trap in path.lower() for trap in [
            "/events/",  # isg.ics.uci.edu/events/*
            "ical",      # Calendar traps
            "tribe",     # Tribe-related traps
            "/pix/"      # ~eppstein/pix (extensive photos)
        ]):
            return False
        
        # Check domain for known trap subdomains
        if any(trap_domain in domain.lower() for trap_domain in [
            "wics.ics",  # wics.ics subdomain
            "ngs.ics",
            "grape.ics"  # grape.ics subdomain
        ]):
            return False
        
        # Check for unwanted query parameters
        query = parsed.query.lower()
        if any(p in query for p in ["replytocom=", "format=amp"]):
            return False
        
        return True

    except (TypeError, ValueError) as e:
        print(f"Error parsing URL {url}: {e}")
        return False
