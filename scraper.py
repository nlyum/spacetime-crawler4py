import re
from urllib.parse import urlparse, urldefrag, urljoin
from bs4 import BeautifulSoup

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


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

    # ---  DEBUG ---
    # print(url,resp.url,resp.status,resp.error,resp.raw_response.url)
    # --------------

    if resp is None:
        return []
    if resp.status != 200:
        return []

    try: 
        soup = BeautifulSoup(resp.raw_response.content, 'lxml')
    except Exception as error_details:
        print(f"*** {error_details} ***")
        return []

    links = set()

    # Finds all the link tags with the href attribute in the HTML
    # Only gets real links and ignores links to emails, and others
    all_page_link_tags = soup.find_all('a', href=True)      

    # Goes through the list of anchor tags found 
    for tag in all_page_link_tags:
        # Extracts the string text from the tag 
        link_string = tag.get('href')    

        # 
        # Makes sure not empty before manipulating URL string
        if link_string:           
            # Removes the part after # in the URL
            # Holds a tuple (0 = URL without fragment, 1 = the fragment part #....)
            link_defragmented = urldefrag(link_string)[0]
            # Converts the URL from relative path to absolute 
            absolute_path = urljoin(resp.url,link_defragmented)
            links.add(absolute_path)
            
# -------- debugging --------
    print(f"\n----- Links found in {resp.raw_response.url}: \n")
    for i in links:
        print(i)
    print(len(links))
    #exit()
 # --------------------------
    return list(links)

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
        # ---- Defragment ----
        # ---- Check if within UCI domain and paths ----
        """ 
        Hint:   Use parsed = urlparse(url). The domain is parsed.netloc. 
                You need to check if parsed.netloc ends with (.endswith()) .ics.uci.edu,
                .cs.uci.edu, etc. AND also check for exact matches (like ics.uci.edu).
        """

        # File type filtering exclued files not of interest

