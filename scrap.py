import requests
from bs4 import BeautifulSoup
import pandas as pd
import tkinter as tk
from tkinter import font
from tkinter import messagebox, filedialog
from tkinter import ttk
from urllib.parse import urljoin, urlparse, urldefrag
import threading
import logging
import concurrent.futures
import time
import re
from urllib.robotparser import RobotFileParser
import gc
import webbrowser

# Function to check if a URL is valid
def is_valid_url(url):
    VALID_URL_REGEX = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return re.match(VALID_URL_REGEX, url) is not None

# Function to flash the PayPal button 10 times
def flash_paypal_button(count=10):
    if count > 0:
        current_color = donate_button.cget("bg")
        new_color = "red" if current_color == "gold" else "gold"
        donate_button.config(bg=new_color)
        # Schedule the next flash
        root.after(300, flash_paypal_button, count - 1)

# Global flag to control stopping of the scan
stop_scan_flag = threading.Event()
MAX_THREADS = 5  # Reduced number of threads for stability
RATE_LIMIT = 1  # Default delay in seconds between requests

# Logging setup
logging.basicConfig(filename='scraper.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s %(message)s')

# Configurable headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# Regular expressions for emails and phone numbers
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_REGEX = re.compile(r'\+?\d[\d\s.-]{7,14}\d')

def load_robots_txt(url):
    parsed_url = urlparse(url)
    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
    rp = RobotFileParser()
    rp.set_url(robots_url)
    try:
        rp.read()
        verbose_output.insert(tk.END, f"Loaded robots.txt from {robots_url}\n")
        verbose_output.see(tk.END)
        logging.info(f"Loaded robots.txt from {robots_url}")
    except Exception as e:
        verbose_output.insert(tk.END, f"Failed to load robots.txt: {e}\n")
        verbose_output.see(tk.END)
        logging.warning(f"Failed to load robots.txt: {e}")
        rp = None
    return rp

def can_fetch_url(rp, url):
    if rp is None:
        return True  # If robots.txt could not be loaded, assume it's safe to fetch
    return rp.can_fetch(HEADERS['User-Agent'], url)

def scrape_page(url, tags, classes, attribute, rp):
    if stop_scan_flag.is_set() or (rp and not can_fetch_url(rp, url)):
        return []

    try:
        time.sleep(rate_limit_scale.get())  # Dynamic rate limiting
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        verbose_output.insert(tk.END, f"Failed to retrieve {url}: {e}\n")
        verbose_output.see(tk.END)
        logging.error(f"Failed to retrieve {url}: {e}")
        return []

    try:
        soup = BeautifulSoup(response.content, 'html.parser')
        data = []

        # Extracting emails and phone numbers if requested
        if search_emails_var.get() == 1:
            emails = EMAIL_REGEX.findall(soup.get_text())
            for email in emails:
                data.append({'URL': url, 'Content': email})

        if search_phones_var.get() == 1:
            phone_numbers = PHONE_REGEX.findall(soup.get_text())
            for phone in phone_numbers:
                data.append({'URL': url, 'Content': phone})

        # Extracting specified tags and attributes
        for tag in tags:
            if classes:
                for cls in classes:
                    elements = soup.find_all(tag, class_=cls)
                    for element in elements:
                        if stop_scan_flag.is_set():
                            return []
                        if attribute == "text":
                            data.append({'URL': url, 'Content': element.get_text(strip=True)})
                        else:
                            attr_value = element.get(attribute)
                            if attr_value:
                                data.append({'URL': url, 'Content': attr_value})
            else:
                elements = soup.find_all(tag)
                for element in elements:
                    if stop_scan_flag.is_set():
                        return []
                    if attribute == "text":
                        data.append({'URL': url, 'Content': element.get_text(strip=True)})
                    else:
                        attr_value = element.get(attribute)
                        if attr_value:
                            data.append({'URL': url, 'Content': attr_value})

        return data

    finally:
        response.close()
        del response, soup
        gc.collect()  # Trigger garbage collection

def get_internal_links(url, soup, base_domain):
    links = set()
    for a_tag in soup.find_all('a', href=True):
        link = urljoin(url, a_tag['href'])
        parsed_link = urlparse(link)

        # Ensure the link is within the base domain and not malformed
        if parsed_link.netloc == base_domain and is_valid_url(link):
            normalized_link = normalize_url(link)
            links.add(normalized_link)
    return links

def normalize_url(url):
    # Normalize URL to remove fragments and trailing slashes
    parsed_url = urlparse(url)
    cleaned_url, _ = urldefrag(parsed_url.geturl())
    return cleaned_url.lower().rstrip('/')

def crawl_site(url, tags, classes, attribute, crawl_links_only=False, rp=None):
    base_domain = urlparse(url).netloc
    visited = set()
    to_visit = set([normalize_url(url)])
    all_links = set()  # This will store all the links found during crawling
    all_data = []  # This will store all the data scraped if crawl_links_only is False
    total_pages = len(to_visit)  # Initial number of pages to visit

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        while to_visit:
            current_url = to_visit.pop()
            if current_url in visited:
                continue
            visited.add(current_url)

            response = None  # Ensure response is defined
            try:
                response = requests.get(current_url, headers=HEADERS, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'html.parser')
                
                if crawl_links_only:
                    new_links = get_internal_links(current_url, soup, base_domain)
                    all_links.update(new_links)
                    to_visit.update(new_links)
                else:
                    page_data = scrape_page(current_url, tags, classes, attribute, rp)
                    all_data.extend(page_data)
                    new_links = get_internal_links(current_url, soup, base_domain)
                    to_visit.update(new_links)
                
                # Update progress bar and statistics
                total_pages += len(new_links)
                progress = len(visited) / total_pages * 100
                progress_bar['value'] = progress
                root.update_idletasks()

            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve {current_url}: {e}")
            finally:
                if response is not None:
                    response.close()  # Ensure response is closed only if it was initialized

    return all_links if crawl_links_only else all_data

def scrape_data():
    stop_scan_flag.clear()  # Reset the flag when starting a new scan
    progress_bar['value'] = 0  # Reset the progress bar

    # Run the scraping in a separate thread
    thread = threading.Thread(target=_scrape_data_thread)
    thread.start()

def _scrape_data_thread():
    url = url_entry.get()
    tags = [tag.strip() for tag in tags_entry.get().split(",")]
    classes = [cls.strip() for cls in classes_entry.get().split(",") if cls.strip()]
    attribute = attribute_choice.get()
    crawl_links_only = crawl_links_var.get() == 1
    
    rp = load_robots_var.get() == 1 and load_robots_txt(url) or None
    
    start_time = time.time()  # Start timing the crawl
    all_data = []  # Initialize all_data to store results

    if crawl_option.get() == 1:  # Crawl entire site
        if crawl_links_only:
            all_links = crawl_site(url, tags, classes, attribute, crawl_links_only=True, rp=rp)
            display_links(all_links)
        else:
            all_data = crawl_site(url, tags, classes, attribute, rp=rp)
            display_data(all_data)
    else:  # Scrape single page
        all_data = scrape_page(url, tags, classes, attribute, rp)
        display_data(all_data)
    
    end_time = time.time()  # End timing the crawl
    elapsed_time = end_time - start_time

    # Update stats
    stats_label.config(text=f"Pages crawled: {len(all_data) if not crawl_links_only else len(all_links)} | Time taken: {elapsed_time:.2f} seconds")

    # Flash the PayPal button 10 times when done
    flash_paypal_button()



def display_data(data):
    if not data:
        messagebox.showwarning("No Data", "No data found with the specified parameters.")
        return

    df = pd.DataFrame(data)

    # Adjust Treeview column width based on the longest content
    max_content_width = max(df['Content'].apply(len)) * 10 if not df.empty else 100  # Estimate width
    tree.column("Content", width=max_content_width)

    # Display data in the Treeview widget
    for i in tree.get_children():
        tree.delete(i)
    for index, row in df.iterrows():
        tree.insert("", "end", values=(row['URL'], row['Content']))

def display_links(links):
    for i in tree.get_children():
        tree.delete(i)
    for link in sorted(links):
        tree.insert("", "end", values=(link, ""))

def export_data(export_format):
    df = scrape_data_for_export()
    if df is not None and not df.empty:
        file_types = [("CSV files", "*.csv")] if export_format == "csv" else [("JSON files", "*.json")]
        file_path = filedialog.asksaveasfilename(defaultextension=f".{export_format}", filetypes=file_types)
        if file_path:
            if export_format == "csv":
                df.to_csv(file_path, index=False)
            elif export_format == "json":
                df.to_json(file_path, orient='records', lines=True)
            elif export_format == "excel":
                df.to_excel(file_path, index=False)
            messagebox.showinfo("Success", f"Data exported successfully as {export_format.upper()}.")

def scrape_data_for_export():
    url = url_entry.get()
    tags = [tag.strip() for tag in tags_entry.get().split(",")]
    classes = [cls.strip() for cls in classes_entry.get().split(",") if cls.strip()]
    attribute = attribute_choice.get()
    crawl_links_only = crawl_links_var.get() == 1
    
    rp = load_robots_var.get() == 1 and load_robots_txt(url) or None
    
    if crawl_option.get() == 1:  # Crawl entire site
        if crawl_links_only:
            all_links = crawl_site(url, tags, classes, attribute, crawl_links_only=True, rp=rp)
            return pd.DataFrame({'URL': list(all_links)})
        else:
            return pd.DataFrame(crawl_site(url, tags, classes, attribute, rp=rp))
    else:  # Scrape single page
        return pd.DataFrame(scrape_page(url, tags, classes, attribute, rp))

def copy_to_clipboard(event):
    selected_items = tree.selection()
    selected_text = ""
    for item in selected_items:
        selected_values = tree.item(item, 'values')
        selected_text += "\t".join(selected_values) + "\n"
    root.clipboard_clear()
    root.clipboard_append(selected_text)

def stop_scan():
    stop_scan_flag.set()  # Signal threads to stop
    verbose_output.insert(tk.END, "Stop button pressed, stopping scan...\n")
    verbose_output.see(tk.END)

def clear_results():
    for i in tree.get_children():
        tree.delete(i)
    verbose_output.delete(1.0, tk.END)
    verbose_output.insert(tk.END, "Results cleared.\n")

def open_paypal():
    # Replace with your actual PayPal donation link
    paypal_url = "https://www.paypal.com/donate/?hosted_button_id=VST8PNC48TKX2"
    webbrowser.open(paypal_url)

def update_rate_limit_label(value):
    rate_limit_label.config(text=f"Rate Limit: {value} seconds")

# Initialize Tkinter
root = tk.Tk()
root.title("Advanced Web Scraper")
root.geometry("1000x700")
root.resizable(True, True)

# Define style
style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 10))
style.configure("TButton", font=("Helvetica", 12), padding=5)
style.configure("TFrame", background="#f0f0f0")

# Create a header frame
header_frame = ttk.Frame(root, padding="10 10 10 10")
header_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
header_frame.columnconfigure(0, weight=1)

# Header Label
header_label = ttk.Label(header_frame, text="Advanced Web Scraper", font=("Helvetica", 16, "bold"), anchor="center")
header_label.grid(row=0, column=0, sticky="ew")

# Create a main content frame
content_frame = ttk.Frame(root, padding="10 10 10 10")
content_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)

# URL Entry
ttk.Label(content_frame, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
url_entry = ttk.Entry(content_frame, width=50)
url_entry.grid(row=0, column=1, padx=5, pady=5)
url_entry.insert(0, "https://www.sasqnet.com")  # Default URL

# HTML Tags Entry
ttk.Label(content_frame, text="HTML Tags (comma-separated):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
tags_entry = ttk.Entry(content_frame, width=50)
tags_entry.grid(row=1, column=1, padx=5, pady=5)

# HTML Classes Entry
ttk.Label(content_frame, text="HTML Classes (comma-separated):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
classes_entry = ttk.Entry(content_frame, width=50)
classes_entry.grid(row=2, column=1, padx=5, pady=5)

# Attribute Choice Combobox
ttk.Label(content_frame, text="Attribute to Scrape:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
attribute_choice = ttk.Combobox(content_frame, values=["text", "href", "src", "alt"], width=47)
attribute_choice.grid(row=3, column=1, padx=5, pady=5)
attribute_choice.current(0)  # Default to 'text'

# Crawl Options
crawl_option = tk.IntVar(value=0)
ttk.Radiobutton(content_frame, text="Scrape Single Page", variable=crawl_option, value=0).grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
ttk.Radiobutton(content_frame, text="Crawl Entire Site", variable=crawl_option, value=1).grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)

# Crawl Links Only Option
crawl_links_var = tk.IntVar(value=0)
ttk.Checkbutton(content_frame, text="Crawl Only for Links", variable=crawl_links_var).grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

# Rate Limit Slider
rate_limit_label = ttk.Label(content_frame, text=f"Rate Limit: {RATE_LIMIT} seconds")
rate_limit_label.grid(row=6, column=0, sticky=tk.W, padx=5, pady=5)
rate_limit_scale = ttk.Scale(content_frame, from_=0.1, to=10.0, orient=tk.HORIZONTAL, command=update_rate_limit_label)
rate_limit_scale.set(RATE_LIMIT)
rate_limit_scale.grid(row=6, column=1, padx=5, pady=5)

# Respect robots.txt Option
load_robots_var = tk.IntVar(value=0)
ttk.Checkbutton(content_frame, text="Respect robots.txt", variable=load_robots_var).grid(row=7, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

# Email and Phone Number Search Options
search_emails_var = tk.IntVar(value=0)
ttk.Checkbutton(content_frame, text="Search for Emails", variable=search_emails_var).grid(row=8, column=0, sticky=tk.W, padx=5, pady=5)

search_phones_var = tk.IntVar(value=0)
ttk.Checkbutton(content_frame, text="Search for Phone Numbers", variable=search_phones_var).grid(row=8, column=1, sticky=tk.W, padx=5, pady=5)

# Progress Bar
progress_bar = ttk.Progressbar(content_frame, orient='horizontal', mode='determinate', length=400)
progress_bar.grid(row=9, column=0, columnspan=2, pady=10)

# Control Buttons Frame
button_frame = ttk.Frame(content_frame)
button_frame.grid(row=10, column=0, columnspan=2, pady=10)

# Control Buttons
scrape_button = ttk.Button(button_frame, text="Scrape Data", command=scrape_data)
scrape_button.grid(row=0, column=0, padx=5)

stop_button = ttk.Button(button_frame, text="Stop Scan", command=stop_scan)
stop_button.grid(row=0, column=1, padx=5)

clear_button = ttk.Button(button_frame, text="Clear Results", command=clear_results)
clear_button.grid(row=0, column=2, padx=5)

# Export Buttons Frame
export_button_frame = ttk.Frame(content_frame)
export_button_frame.grid(row=11, column=0, columnspan=2, pady=10)

# Export Buttons
export_csv_button = ttk.Button(export_button_frame, text="Export to CSV", command=lambda: export_data("csv"))
export_csv_button.grid(row=0, column=0, padx=5)

export_json_button = ttk.Button(export_button_frame, text="Export to JSON", command=lambda: export_data("json"))
export_json_button.grid(row=0, column=1, padx=5)

export_excel_button = ttk.Button(export_button_frame, text="Export to Excel", command=lambda: export_data("excel"))
export_excel_button.grid(row=0, column=2, padx=5)

# Treeview for displaying scraped data or links
tree = ttk.Treeview(content_frame, columns=("URL", "Content"), show="headings", selectmode="extended")
tree.heading("URL", text="URL")
tree.heading("Content", text="Scraped Content")
tree.column("URL", width=300, anchor=tk.W)
tree.column("Content", width=300, anchor=tk.W)
tree.grid(row=12, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

# Enable selection and copying from Treeview
tree.bind("<Control-c>", copy_to_clipboard)

# Create a bold font
bold_font = font.Font(weight="bold")

# Text widget for verbose output
verbose_output = tk.Text(content_frame, height=5, wrap=tk.WORD, bg="black", fg="green", font=bold_font)
verbose_output.grid(row=13, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

# Add scrollbars
scrollbar_y = ttk.Scrollbar(content_frame, orient="vertical", command=tree.yview)
scrollbar_y.grid(row=12, column=2, sticky='ns')
tree.configure(yscrollcommand=scrollbar_y.set)

scrollbar_x = ttk.Scrollbar(content_frame, orient="horizontal", command=tree.xview)
scrollbar_x.grid(row=14, column=0, columnspan=2, sticky='ew')
tree.configure(xscrollcommand=scrollbar_x.set)

# Configure grid weights for resizing
content_frame.grid_rowconfigure(12, weight=1)
content_frame.grid_columnconfigure(1, weight=1)

# Create a footer frame
footer_frame = ttk.Frame(root, padding="10 10 10 10")
footer_frame.grid(row=2, column=0, columnspan=2, sticky="ew")

# Stats label
stats_label = ttk.Label(footer_frame, text="Pages crawled: 0 | Time taken: 0 seconds", font=("Helvetica", 10))
stats_label.grid(row=0, column=0, pady=5)

# Donation Button (Use tk.Button instead of ttk.Button for background color control)
donate_button = tk.Button(footer_frame, text="Donate with PayPal", command=open_paypal, bg="gold", fg="black", font=("Helvetica", 12, "bold"))
donate_button.grid(row=1, column=0, pady=5)

# Footer text
footer_label = ttk.Label(footer_frame, text="Thank you for supporting this project!", font=("Helvetica", 10))
footer_label.grid(row=2, column=0, pady=5)

# Run the application
root.mainloop()
