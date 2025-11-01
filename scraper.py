import re
import time
import hashlib
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs
from bs4 import BeautifulSoup
import configparser
from collections import defaultdict, Counter

# Global tracking for crawler trap detection and politeness
crawled_urls = []
url_patterns = defaultdict(int)  # Track URL patterns
query_params = defaultdict(int)  # Track query parameters
path_depth = defaultdict(int)    # Track path depths
session_tracker = defaultdict(set)  # Track session-like parameters
domain_last_crawl = defaultdict(float)  # Track last crawl time per domain
page_content_hashes = defaultdict(int)  # Track content similarity
url_visit_count = defaultdict(int)  # Track URL visit frequency
stop_words = set()   # Used for finding most frequent words
word_counter = Counter()    # Tracks word frequency across all pages

def get_allowed_domains():
    """
    Load allowed domains from config.ini file (cached)
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

def get_politeness_delay():
    """
    Get politeness delay from config.ini
    """
    try:
        config = configparser.ConfigParser()
        config.read('config.ini')
        return float(config["CRAWLER"]["POLITENESS"])
    except Exception as e:
        print(f" Error loading politeness delay, using default 1.0s: {e}")
        return 1.0

def check_politeness_delay(url):
    """
    Check if enough time has passed since last crawl of this domain
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        current_time = time.time()
        delay = get_politeness_delay()
        
        if domain in domain_last_crawl:
            time_since_last = current_time - domain_last_crawl[domain]
            if time_since_last < delay:
                wait_time = delay - time_since_last
                print(f" Politeness delay: waiting {wait_time:.2f}s for {domain}")
                time.sleep(wait_time)
        
        domain_last_crawl[domain] = time.time()
        return True
    except Exception as e:
        print(f" Error checking politeness delay: {e}")
        return False

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

def is_similar_page_with_no_info(url, content):
    """
    Detect pages with similar content but no useful information
    """
    try:
        if not content:
            return True
        
        # Create content hash for similarity detection
        soup = BeautifulSoup(content, "html.parser")
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text content
        text_content = soup.get_text()
        
        # Check for very little text content
        if len(text_content.strip()) < 100:  # Less than 100 characters
            return True
        
        # Check for mostly navigation/boilerplate content
        nav_keywords = ['navigation', 'menu', 'sidebar', 'footer', 'header', 'breadcrumb']
        nav_count = sum(1 for keyword in nav_keywords if keyword in text_content.lower())
        
        if nav_count > 3 and len(text_content) < 500:  # Mostly navigation
            return True
        
        # Create hash of content for similarity detection
        content_hash = hashlib.md5(text_content.encode()).hexdigest()
        page_content_hashes[content_hash] += 1
        
        # If we've seen this exact content more than 3 times, it's likely a template
        if page_content_hashes[content_hash] > 3:
            return True
        
        return False
        
    except Exception as e:
        print(f"Error checking similar page for {url}: {e}")
        return True
""" 
def is_dead_url(resp):
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
 """
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
    """
    try:
        if not content:
            return False
        
        soup = BeautifulSoup(content, "html.parser")
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "header", "footer"]):
            script.decompose()
        
        # Get text content
        text_content = soup.get_text()
        
        # Check for minimum text content (at least 200 characters)
        if len(text_content.strip()) < 200:
            return False
        
        # Check for meaningful content indicators
        content_indicators = [
            'article', 'main', 'content', 'text', 'paragraph', 'section'
        ]
        
        # Look for content-rich elements
        content_elements = soup.find_all(['article', 'main', 'div', 'section', 'p'])
        if len(content_elements) < 3:  # Need at least some structure
            return False
        
        # Check for reasonable text density
        total_text = len(text_content)
        if total_text < 500:  # At least 500 characters of text
            return False
        
        return True
        
    except Exception as e:
        print(f"Error checking textual content: {e}")
        return False

def track_url_pattern(url):
    """
    Track URL patterns for trap detection
    """
    try:
        parsed = urlparse(url)
        
        # Create a pattern by normalizing the URL
        pattern = f"{parsed.netloc}{parsed.path}"
        # Remove numbers and replace with placeholder
        pattern = re.sub(r'\d+', 'N', pattern)
        
        url_patterns[pattern] += 1
        
        # Track query parameters
        query_params_list = parse_qs(parsed.query)
        for param in query_params_list.keys():
            query_params[param] += 1
        
        # Track path depth
        path_parts = [p for p in parsed.path.split('/') if p]
        path_depth[len(path_parts)] += 1
        
        # Track URL visit count
        url_visit_count[url] += 1
        
    except Exception as e:
        print(f"Error tracking URL pattern for {url}: {e}")

def load_stopwords(filename="stopwords.txt"):
    """
    Load stopwords from stored file
    Used for : 50 most common words
    """
    stopwords = set()
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                word = line.strip().lower()
                if word:
                    stopwords.add(word)
    except FileNotFoundError:
        print(f"Warning: stopwords file '{filename}' not found.")
    return stopwords

def count_page_words_frequency(resp):
    """
    Extracts words from the passed URL and stores in word counter
    Ignores stopwords, HTML markup and only counts letters [a-z] 
    to be considerred a word
    """
    global stop_words
    stop_words = load_stopwords()
    try:
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")

        # Removes unnecessary tags 
        for tag in soup(["script", "style", "nav", "header", "footer"]):
            tag.decompose()
        # Gets only the readable text
        text = soup.get_text(separator=" ")
        text = text.lower()

        # filters out # or symbols, only letters a-z
        words = re.findall(r"[a-z]+", text)

        # goes through found words and if not a stop word adds it to global counter with +1 to its frequency
        for word in words:
            if word not in stop_words:
                word_counter[word] += 1

    except Exception as e:
        print(f"Error counting words: {e}")

def save_top_words_to_file(filename="top_words.txt", n=50):
    """
    Save the n most common words to text file.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Top {n} Most Common Words (excluding stopwords)\n")
            f.write("=" * 50 + "\n")
            for word, count in word_counter.most_common(n):
                f.write(f"{word:<20} {count}\n")
    except Exception as e:
        print(f"Error saving top words: {e}")

def scraper(url, resp):
    """
    Main scraper function with comprehensive trap detection and content analysis
    """
    try:
        # Check politeness delay
        check_politeness_delay(url)
        
        # Check if response is valid
        if resp.status != 200:
            print(f" Invalid response status {resp.status} for {url}")
            return []
        
        """if is_dead_url(resp):
            print(f" Dead URL detected: {url}")
            return [] """
        
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
        
        # Check for similar pages with no info
        if is_similar_page_with_no_info(url, content):
            print(f" Similar page with no info detected: {url}")
            return []
        # Track URL pattern for trap detection
        track_url_pattern(url)
        
        # Tracks frequency of words 
        count_page_words_frequency(resp)

        # Extract links from the page
        links = extract_next_links(url, resp)
        valid_links = []
        
        for link in links:
            # Check if URL is valid (domain, file extensions, etc.)
            if not is_valid(link):
                continue
            
            # Check for infinite traps
            if is_infinite_trap(link):
                print(f" Infinite trap detected: {link}")
                continue
            
            # Check URL visit frequency (avoid crawling same URL too many times)
            if url_visit_count[link] > 2:
                print(f" URL visited too many times: {link}")
                continue
            
            valid_links.append(link)
            crawled_urls.append(link)
        
        print(f" Successfully processed {url} - found {len(valid_links)} valid links")
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
    save_top_words_to_file("top_words.txt", 50)

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
        
        # Check for unwanted query parameters
        query = parsed.query.lower()
        if any(p in query for p in ["replytocom=", "format=amp"]):
            return False
        
        return True

    except TypeError:
        print ("TypeError for ", parsed)
        raise

def get_all_crawled_urls():
    """
    Return a list of all URLs that have been crawled
    """
    return crawled_urls.copy()

def print_crawled_urls():
    """
    Print all crawled URLs
    """
    print(f"\n ALL CRAWLED URLs ({len(crawled_urls)} total):")
    print("="*60)
    for i, url in enumerate(crawled_urls, 1):
        print(f"{i:3d}. {url}")
    print("="*60)

def reset_crawled_urls():
    """
    Reset the list of crawled URLs
    """
    global crawled_urls
    crawled_urls.clear()
    print(" Crawled URLs list reset")

def get_unique_crawled_urls():
    """
    Return unique crawled URLs (removes duplicates)
    """
    unique_urls = list(dict.fromkeys(crawled_urls))  # Preserves order
    return unique_urls

def print_unique_crawled_urls():
    """
    Print unique crawled URLs
    """
    unique_urls = get_unique_crawled_urls()
    print(f"\n🔗 UNIQUE CRAWLED URLs ({len(unique_urls)} unique out of {len(crawled_urls)} total):")
    print("="*60)
    for i, url in enumerate(unique_urls, 1):
        print(f"{i:3d}. {url}")
    print("="*60)

def save_all_urls_to_file(filename="all_crawled_urls.txt"):
    """
    Save all crawled URLs to a text file
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"ALL CRAWLED URLs ({len(crawled_urls)} total)\n")
            f.write("="*60 + "\n")
            for i, url in enumerate(crawled_urls, 1):
                f.write(f"{i:3d}. {url}\n")
            f.write("="*60 + "\n")
        print(f" All crawled URLs saved to: {filename}")
    except Exception as e:
        print(f" Error saving all URLs to file: {e}")

def save_unique_urls_to_file(filename="unique_crawled_urls.txt"):
    """
    Save unique crawled URLs to a text file
    """
    try:
        unique_urls = get_unique_crawled_urls()
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"UNIQUE CRAWLED URLs ({len(unique_urls)} unique out of {len(crawled_urls)} total)\n")
            f.write("="*60 + "\n")
            for i, url in enumerate(unique_urls, 1):
                f.write(f"{i:3d}. {url}\n")
            f.write("="*60 + "\n")
        print(f" Unique crawled URLs saved to: {filename}")
    except Exception as e:
        print(f" Error saving unique URLs to file: {e}")

def save_crawl_results():
    """
    Save both all URLs and unique URLs to text files
    """
    print("\n Saving crawl results to files...")
    save_all_urls_to_file()
    save_unique_urls_to_file()
    save_top_words_to_file("top_words.txt", 50)
    print(" Crawl results saved successfully!")

def reset_all_tracking():
    """
    Reset all tracking data for a fresh start
    """
    global crawled_urls, url_patterns, query_params, path_depth, session_tracker
    global domain_last_crawl, page_content_hashes, url_visit_count
    
    crawled_urls.clear()
    url_patterns.clear()
    query_params.clear()
    path_depth.clear()
    session_tracker.clear()
    domain_last_crawl.clear()
    page_content_hashes.clear()
    url_visit_count.clear()
    
    print(" All tracking data reset")

def get_crawl_statistics():
    """
    Get comprehensive crawl statistics
    """
    unique_urls = get_unique_crawled_urls()
    
    stats = {
        'total_urls': len(crawled_urls),
        'unique_urls': len(unique_urls),
        'duplicate_rate': (len(crawled_urls) - len(unique_urls)) / len(crawled_urls) if crawled_urls else 0,
        'domains_crawled': len(set(urlparse(url).netloc for url in crawled_urls)),
        'avg_path_depth': sum(path_depth.values()) / len(path_depth) if path_depth else 0,
        'most_common_patterns': Counter(url_patterns).most_common(5),
        'most_common_params': Counter(query_params).most_common(5),
        'politeness_delay': get_politeness_delay()
    }
    
    return stats

def print_crawl_statistics():
    """
    Print comprehensive crawl statistics
    """
    stats = get_crawl_statistics()
    
    print("\n" + "="*70)
    print(" COMPREHENSIVE CRAWL STATISTICS")
    print("="*70)
    
    print(f" URL Statistics:")
    print(f"   Total URLs crawled: {stats['total_urls']}")
    print(f"   Unique URLs: {stats['unique_urls']}")
    print(f"   Duplicate rate: {stats['duplicate_rate']:.2%}")
    print(f"   Domains crawled: {stats['domains_crawled']}")
    
    print(f"\n Path Analysis:")
    print(f"   Average path depth: {stats['avg_path_depth']:.1f}")
    
    print(f"\n Most Common URL Patterns:")
    for pattern, count in stats['most_common_patterns']:
        if count > 1:
            print(f"   {pattern}: {count} occurrences")
    
    print(f"\n Most Common Query Parameters:")
    for param, count in stats['most_common_params']:
        print(f"   {param}: {count} occurrences")
    
    print(f"\n Politeness Settings:")
    print(f"   Delay between requests: {stats['politeness_delay']}s")
    
    print("="*70)