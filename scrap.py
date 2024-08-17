import requests
from bs4 import BeautifulSoup
import pandas as pd
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from urllib.parse import urljoin, urlparse
import threading

# Global flag to control stopping of the scan
stop_scan_flag = False

def scrape_page(url, tags, classes, attribute):
    if stop_scan_flag:
        return []
    
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        verbose_output.insert(tk.END, f"Failed to retrieve {url}: {e}\n")
        verbose_output.see(tk.END)
        return []

    soup = BeautifulSoup(response.content, 'html.parser')
    data = []

    for tag in tags:
        if classes:
            for cls in classes:
                elements = soup.find_all(tag, class_=cls)
                for element in elements:
                    if stop_scan_flag:
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
                if stop_scan_flag:
                    return []
                if attribute == "text":
                    data.append({'URL': url, 'Content': element.get_text(strip=True)})
                else:
                    attr_value = element.get(attribute)
                    if attr_value:
                        data.append({'URL': url, 'Content': attr_value})

    return data

def get_internal_links(url, soup, base_domain):
    links = set()
    for a_tag in soup.find_all('a', href=True):
        if stop_scan_flag:
            return links
        link = urljoin(url, a_tag['href'])
        parsed_link = urlparse(link)
        if parsed_link.netloc == base_domain:
            links.add(link)
    return links

def crawl_site(url, tags, classes, attribute, crawl_links_only=False):
    base_domain = urlparse(url).netloc
    visited = set()
    to_visit = {url}
    all_data = []
    all_links = set()

    while to_visit:
        if stop_scan_flag:
            verbose_output.insert(tk.END, "Crawl stopped by user.\n")
            verbose_output.see(tk.END)
            break
        
        current_url = to_visit.pop()
        if current_url in visited:
            continue

        visited.add(current_url)
        verbose_output.insert(tk.END, f"Crawling: {current_url}\n")
        verbose_output.see(tk.END)
        try:
            response = requests.get(current_url)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            verbose_output.insert(tk.END, f"Failed to retrieve {current_url}: {e}\n")
            verbose_output.see(tk.END)
            continue

        soup = BeautifulSoup(response.content, 'html.parser')

        if crawl_links_only:
            new_links = get_internal_links(current_url, soup, base_domain)
            all_links.update(new_links)
        else:
            page_data = scrape_page(current_url, tags, classes, attribute)
            all_data.extend(page_data)
            new_links = get_internal_links(current_url, soup, base_domain)
            to_visit.update(new_links - visited)

    return all_links if crawl_links_only else all_data

def scrape_data():
    global stop_scan_flag
    stop_scan_flag = False  # Reset the flag when starting a new scan

    # Run the scraping in a separate thread
    thread = threading.Thread(target=_scrape_data_thread)
    thread.start()

def _scrape_data_thread():
    url = url_entry.get()
    tags = [tag.strip() for tag in tags_entry.get().split(",")]
    classes = [cls.strip() for cls in classes_entry.get().split(",") if cls.strip()]
    attribute = attribute_choice.get()
    crawl_links_only = crawl_links_var.get() == 1
    
    if crawl_option.get() == 1:  # Crawl entire site
        if crawl_links_only:
            all_links = crawl_site(url, tags, classes, attribute, crawl_links_only=True)
            display_links(all_links)
        else:
            all_data = crawl_site(url, tags, classes, attribute)
            display_data(all_data)
    else:  # Scrape single page
        all_data = scrape_page(url, tags, classes, attribute)
        display_data(all_data)

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
            messagebox.showinfo("Success", f"Data exported successfully as {export_format.upper()}.")

def scrape_data_for_export():
    url = url_entry.get()
    tags = [tag.strip() for tag in tags_entry.get().split(",")]
    classes = [cls.strip() for cls in classes_entry.get().split(",") if cls.strip()]
    attribute = attribute_choice.get()
    crawl_links_only = crawl_links_var.get() == 1
    
    if crawl_option.get() == 1:  # Crawl entire site
        if crawl_links_only:
            all_links = crawl_site(url, tags, classes, attribute, crawl_links_only=True)
            return pd.DataFrame({'URL': list(all_links)})
        else:
            return pd.DataFrame(crawl_site(url, tags, classes, attribute))
    else:  # Scrape single page
        return pd.DataFrame(scrape_page(url, tags, classes, attribute))

def copy_to_clipboard(event):
    selected_items = tree.selection()
    selected_text = ""
    for item in selected_items:
        selected_values = tree.item(item, 'values')
        selected_text += "\t".join(selected_values) + "\n"
    root.clipboard_clear()
    root.clipboard_append(selected_text)

def stop_scan():
    global stop_scan_flag
    stop_scan_flag = True
    verbose_output.insert(tk.END, "Stop button pressed, stopping scan...\n")
    verbose_output.see(tk.END)

def clear_results():
    for i in tree.get_children():
        tree.delete(i)
    verbose_output.delete(1.0, tk.END)
    verbose_output.insert(tk.END, "Results cleared.\n")

# Initialize Tkinter
root = tk.Tk()
root.title("Advanced Web Scraper")
root.geometry("1000x700")
root.resizable(True, True)

# Create and place widgets
tk.Label(root, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=10)
url_entry = tk.Entry(root, width=50)
url_entry.grid(row=0, column=1, padx=10, pady=10)
url_entry.insert(0, "https://www.sasqnet.com")  # Default URL

tk.Label(root, text="HTML Tags (comma-separated):").grid(row=1, column=0, sticky=tk.W, padx=10, pady=10)
tags_entry = tk.Entry(root, width=50)
tags_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="HTML Classes (comma-separated):").grid(row=2, column=0, sticky=tk.W, padx=10, pady=10)
classes_entry = tk.Entry(root, width=50)
classes_entry.grid(row=2, column=1, padx=10, pady=10)

tk.Label(root, text="Attribute to Scrape:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=10)
attribute_choice = ttk.Combobox(root, values=["text", "href", "src", "alt"], width=47)
attribute_choice.grid(row=3, column=1, padx=10, pady=10)
attribute_choice.current(0)  # Default to 'text'

# Add option for crawling the entire site
crawl_option = tk.IntVar(value=0)
tk.Radiobutton(root, text="Scrape Single Page", variable=crawl_option, value=0).grid(row=4, column=0, sticky=tk.W, padx=10, pady=10)
tk.Radiobutton(root, text="Crawl Entire Site", variable=crawl_option, value=1).grid(row=4, column=1, sticky=tk.W, padx=10, pady=10)

# Add option to crawl only for links
crawl_links_var = tk.IntVar(value=0)
tk.Checkbutton(root, text="Crawl Only for Links", variable=crawl_links_var).grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=10)

scrape_button = tk.Button(root, text="Scrape Data", command=scrape_data)
scrape_button.grid(row=6, column=0, pady=10)

stop_button = tk.Button(root, text="Stop Scan", command=stop_scan)
stop_button.grid(row=6, column=1, pady=10)

clear_button = tk.Button(root, text="Clear Results", command=clear_results)
clear_button.grid(row=7, column=0, columnspan=2, pady=10)

export_csv_button = tk.Button(root, text="Export Data to CSV", command=lambda: export_data("csv"))
export_csv_button.grid(row=8, column=0, pady=10)

export_json_button = tk.Button(root, text="Export Data to JSON", command=lambda: export_data("json"))
export_json_button.grid(row=8, column=1, pady=10)

# Treeview for displaying scraped data or links
tree = ttk.Treeview(root, columns=("URL", "Content"), show="headings", selectmode="extended")
tree.heading("URL", text="URL")
tree.heading("Content", text="Scraped Content")
tree.column("URL", width=300, anchor=tk.W)
tree.column("Content", width=300, anchor=tk.W)
tree.grid(row=9, column=0, columnspan=2, padx=10, pady=10, sticky='nsew')

# Enable selection and copying from Treeview
tree.bind("<Control-c>", copy_to_clipboard)

# Verbose output
verbose_output = tk.Text(root, height=10, wrap=tk.WORD)
verbose_output.grid(row=10, column=0, columnspan=2, padx=10, pady=10, sticky='nsew')

# Add scrollbars
scrollbar_y = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
scrollbar_y.grid(row=9, column=2, sticky='ns')
tree.configure(yscrollcommand=scrollbar_y.set)

scrollbar_x = ttk.Scrollbar(root, orient="horizontal", command=tree.xview)
scrollbar_x.grid(row=11, column=0, columnspan=2, sticky='ew')
tree.configure(xscrollcommand=scrollbar_x.set)

# Configure grid weights for resizing
root.grid_rowconfigure(9, weight=1)
root.grid_columnconfigure(1, weight=1)

# Run the application
root.mainloop()
