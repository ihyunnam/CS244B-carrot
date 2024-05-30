import requests

def fetch_html(url):
    try:
        response = requests.get(url)
        # Check if the request was successful
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

if __name__ == "__main__":
    url = "https://www.google.com"
    html_content = fetch_html(url)
    if html_content:
        print(html_content)
