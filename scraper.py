"""
Web Crawler Scraper
Main scraper module with comprehensive trap detection and report generation
"""

import re
import json
import time
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs, urlunparse
from bs4 import BeautifulSoup, Comment
from collections import defaultdict, Counter

unique_urls = set()  # Unique URLs crawled
subdomain_urls = defaultdict(set)  # Store unique URLs per subdomain

# Longest page tracking (using dict like provided code)
LONGEST_PAGE = {"url": None, "count": 0}

# ============================================================================
# CONFIGURATION FUNCTIONS
# ============================================================================
stop_words = set()
word_counter = Counter()

# Similarity detection tracking
url_to_word_vector = {}  # Store word vectors (TF-IDF) per URL
document_frequencies = defaultdict(int)  # Track how many docs contain each word
total_documents = 0
exact_content_hashes = set()  # Store exact content hashes for duplicate detection

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
        
        # Check for excessive query parameters (potential trap) - relaxed
        if len(query_params_list) > 35:  # Increased from 5 to 15 to 25 to 35
            return True
        
        # Check for URL patterns that might be traps
        path = parsed.path.lower()
        
        # Calendar/date-based traps
        if re.search(r'/(calendar|events|archive|day)/(\d{4})/(\d{1,2})', path):
            return True
        # if re.search(r'/(\d{4})/(\d{1,2})/(\d{1,2})', path):
        #     return True
        
        # Pagination traps (excessive page numbers) - only block really deep pagination
        if re.search(r'/page/\d{5,}', path):  # Increased from 3+ to 4+ to 5+
            return True
        
        # Search result traps
        if '/search' in path and len(query_params_list) > 10:  # Increased from 3 to 10
            return True
        
        # Check for excessive path depth - relaxed
        path_parts = [p for p in path.split('/') if p]
        if len(path_parts) > 20:  # Increased from 6 to 10 to 15 to 20
            return True
        
        # Don't block all PHP/JSP files - only block if clearly dynamic
        # suspicious_extensions = ['.php', '.asp', '.jsp', '.cgi']
        # if any(path.endswith(ext) for ext in suspicious_extensions):
        #     return True
        
        # Check for URL shorteners or redirects
        redirect_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if parsed.netloc.lower() in redirect_domains:
            return True
        
        # Check for admin/private areas
        # private_paths = ['/admin', '/private', '/internal', '/secure', '/login', '/logout']
        # if any(private_path in path for private_path in private_paths):
        #     return True
        
        return False
        
    except Exception as e:
        print(f"Error checking infinite trap for {url}: {e}")
        return False

# ============================================================================
# CONTENT QUALITY DETECTION FUNCTIONS
# ============================================================================

def is_large_file_with_low_value(url, content):
    """
    Detect very large files with low information value
    """
    try:
        if not content:
            return False
        
        content_size = len(content)
        
        # Only check for extremely large files (larger than 10MB)
        if content_size > 15 * 1024 * 1024:  # 15MB (increased from 1MB to 10MB to 15MB)
            # Check if it's a binary file or has low text content
            try:
                content_str = content.decode('utf-8', errors='ignore')
                text_ratio = len(content_str) / content_size
                
                # If less than 1% is readable text, it's likely a binary file
                if text_ratio < 0.01:  # Very relaxed from 0.1 to 0.01
                    return True
                    
            except:
                return True

        return False
        
    except Exception as e:
        print(f"Error checking large file for {url}: {e}")
        return False

def has_high_textual_content(content):
    """
    Check if page has high textual information content
    VERY RELAXED for maximum coverage
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
        
        # Very minimal word count check (words of 3+ characters)
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text_content.lower())
        if len(words) < 3:  # Need at least 3 words (very relaxed) changed from 10 to 5 to 3
            return False
        
        return True
        
    except Exception as e:
        print(f"Error checking textual content: {e}")
        return False

# ============================================================================
# TEXT PROCESSING FUNCTIONS
# ============================================================================

def load_stopwords(filename="stopwords.txt"):
    """
    Load stopwords from stored file
    Used for : 50 most common words
    """
    global stop_words
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                word = line.strip().lower()
                if word:
                    stop_words.add(word)
    except FileNotFoundError:
        print(f"Warning: stopwords file '{filename}' not found.")
    return stop_words

def visible_text_from_soup(soup: BeautifulSoup) -> str:
    """
    Extract visible text from soup, removing non-content elements
    Drop non-content tags: JS/CSS/inert markup, cuts menus/footers
    """
    # Remove JS/CSS/inert markup, cuts menus/footers
    for t in soup(["script", "style", "noscript", "template", "svg", "canvas", "nav", "header", "footer"]):
        t.decompose()
    
    # Drop comments
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
    
    # Drop hidden elements (non-visible)
    for el in soup.select('[hidden], [aria-hidden="true"], [style*="display:none"], [style*="visibility:hidden"]'):
        el.decompose()
    
    # Get visible text
    text = soup.get_text(" ", strip=True)
    text = text.lower()
    return text
    
def count_words(text: str) -> int:
    """
    Count words in text and update global word counter
    Only load stop words once and not every single time
    """
    global stop_words, word_counter
    
    # Only load stop words once
    if not stop_words:
        load_stopwords()
    
    # Find all words (alphanumeric, like provided code)
    words = re.findall(r"\b[a-z]{3,}\b", text.lower())
    
    # Goes through found words and if not a stop word adds it to global counter with +1 to its frequency
    for word in words:
        if word.lower() not in stop_words:
            word_counter[word.lower()] += 1
    
    return len(words)

def update_longest(url: str, count: int) -> None:
    """
    Update the longest page tracking if this page has more words
    """
    global LONGEST_PAGE
    
    if count > LONGEST_PAGE["count"]:
        LONGEST_PAGE["url"] = url
        LONGEST_PAGE["count"] = count

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
    Note: Word counting is now done in extract_next_links()
    """
    global unique_urls, subdomain_urls
    
    # Add to unique URLs
    unique_urls.add(url)
    
    # Track subdomain - add this URL to subdomain's set
    # Normalize by removing www. prefix to avoid duplicates
    try:
        parsed = urlparse(url)
        subdomain = parsed.netloc.lower()
        # Remove www. prefix if present
        if subdomain.startswith('www.'):
            subdomain = subdomain[4:]  # Remove 'www.'
        subdomain_urls[subdomain].add(url)
    except Exception:
        pass  # Silently fail if parsing fails
    
    # Save report periodically (every 50 URLs)
    if len(unique_urls) % 50 == 0:
        save_report_json()
        save_unique_urls_to_file()

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
        # Use visible_text_from_soup to get clean text
        text_content = visible_text_from_soup(soup)
        # Extract words (alphanumeric, 2+ chars, similar to count_words but without stopwords filtering for similarity)
        words = re.findall(r"[A-Za-z0-9]+", text_content)
        
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

def save_unique_urls_to_file(filename="unique_urls.txt"):
    """
    Save all unique URLs to a text file, overwriting with latest complete list
    Updates live every 50 URLs
    """
    global unique_urls
    
    try:
        # Sort URLs for consistent output
        sorted_urls = sorted(unique_urls)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"UNIQUE CRAWLED URLs ({len(sorted_urls)} total)\n")
            f.write("=" * 70 + "\n\n")
            for i, url in enumerate(sorted_urls, 1):
                f.write(f"{i:6d}. {url}\n")
            f.write("\n" + "=" * 70 + "\n")
            f.write(f"Total unique URLs: {len(sorted_urls)}\n")
    except Exception:
        pass  # Silent failure

def save_report_json(filename="crawl_report.json"):
    """
    Save current report data to JSON file
    Includes: unique pages count, longest page, top 50 words, and subdomains
    """
    global unique_urls, subdomain_urls, LONGEST_PAGE, word_counter
    
    try:
        # Get top 50 most common words from word_counter
        top_50_words = [(word, count) for word, count in word_counter.most_common(50)]
        
        # Get subdomains in alphabetical order with counts
        subdomain_list = [(subdomain, len(urls)) for subdomain, urls in sorted(subdomain_urls.items())]
        
        # Build report dictionary
        report = {
            "unique_pages_count": len(unique_urls),
            "longest_page": {
                "url": LONGEST_PAGE["url"] if LONGEST_PAGE["url"] else None,
                "word_count": LONGEST_PAGE["count"] if LONGEST_PAGE["count"] else 0
            },
            "top_50_words": top_50_words,
            "subdomains": subdomain_list
        }
        
        # Save to JSON file with UTF-8 encoding
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except Exception:
        pass  # Silent failure

# ============================================================================
# MAIN SCRAPER FUNCTIONS
# ============================================================================

def scraper(url, resp):
    """
    Main scraper function with comprehensive trap detection and content analysis
    """
    # Politeness delay - wait 0.5 seconds before processing each URL
    time.sleep(0.5)
    
    try:
        # Check if response is valid
        if resp.status != 200:
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
        # NOTE: Near-duplicate detection is very aggressive and may stop crawl early
        # if has_similar_content(url, content):
        #     return []
        
        # Update report tracking with this URL
        update_report(url, content)
        
        # Extract links from the page
        links = extract_next_links(url, resp)
        valid_links = []
        
        for link in links:
            normalized_link = canonicalize_trailing_slash(link)
            # Check if URL is valid (domain, file extensions, etc.)
            if not is_valid(normalized_link):
                continue
            
            # Check for infinite traps
            if is_infinite_trap(normalized_link):
                continue
            
            valid_links.append(normalized_link)
        
        return valid_links
        
    except Exception as e:
        print(f" Error in scraper for {url}: {e}")
        return []

def canonicalize_trailing_slash(u: str) -> str:
    p = urlparse(u)
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        #remove the trailing slash
        path = path[:-1]
    p = p._replace(path=path)
    return urlunparse(p)

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
        
        # Count words for the page (like provided code)
        visible_text = visible_text_from_soup(soup)
        word_count = count_words(visible_text)
        update_longest(url, word_count)
        
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
        
        allowed_domains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]

        domain = parsed.netloc.lower()
        if not any(domain.endswith(d) for d in allowed_domains):
            return False
        
        # Check for unwanted file extensions
        path = parsed.path.lower()
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpg|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|docs"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", path):
            return False
        
        # Check for unwanted paths
        if any(s in path for s in ["/calendar", "/feed", "/tag/"]):
            return False
        
        if any(trap in path.lower() for trap in [
            "/events/",     # isg.ics.uci.edu/events/* (calendar)
            "/ical/",       # Calendar traps - more specific (not just "ical")
            "tribe-",       # Tribe-related traps - more specific
            "/pix/",        # ~eppstein/pix (extensive photos)
            "doku.php"      # doku.php traps
        ]):
            return False
        
        # Check domain for known trap subdomains
        if any(trap_domain in domain.lower() for trap_domain in [
            "grape.ics",     # grape.ics subdomain (infinite trap)
            "gitlab.ics",    # gitlab.ics.uci.edu (every commit is a separate page)
            "fano.ics"       # fano.ics.uci.edu/ca/rules/
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
    