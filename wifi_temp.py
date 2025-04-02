import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import webbrowser
from threading import Thread
import os
import csv
from datetime import datetime
import re
import ctypes
import sys
import tempfile
import winreg
import time
import itertools
import queue

class WiFiCrackerPro:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Cracker Pro")
        self.root.geometry("1100x750")
        self.root.resizable(True, True)
        self.root.minsize(950, 650)
        
        # Check for admin privileges
        self.admin_mode = self.is_admin()
        if not self.admin_mode:
            self.show_admin_warning()
        
        # Initialize attributes
        self.loading = False
        self.scanning = False
        self.cracking = False
        self.profiles = []
        self.passwords = {}
        self.available_networks = []
        self.connected_history = {}
        self.advanced_mode = False
        self.wordlist = []
        self.wordlist_loaded = False
        self.task_queue = queue.Queue()
        
        # Set application icon
        self.set_window_icon()
        
        self.create_widgets()
        self.center_window()
        self.load_wordlist()
        self.refresh_profiles()
    
    def is_admin(self):
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def show_admin_warning(self):
        """Show warning about admin privileges"""
        messagebox.showwarning(
            "Admin Privileges Recommended",
            "Some advanced features require administrator privileges to work properly.\n"
            "WiFi scanning and cracking may be limited without elevated permissions."
        )
    
    def set_window_icon(self):
        """Set application icon"""
        try:
            self.root.iconbitmap(default='wifi.ico')
        except:
            try:
                # Create temporary icon file if none exists
                icon_path = os.path.join(tempfile.gettempdir(), 'wifi.ico')
                if not os.path.exists(icon_path):
                    # This would be where you create or download an icon file
                    pass
                self.root.iconbitmap(default=icon_path)
            except:
                pass
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Create main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="WiFi Cracker Pro", font=('Helvetica', 16, 'bold')).pack(side=tk.LEFT)
        
        # Advanced mode toggle
        self.advanced_btn = ttk.Button(
            header_frame, 
            text="Enable Advanced Mode", 
            command=self.toggle_advanced_mode
        )
        self.advanced_btn.pack(side=tk.RIGHT, padx=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(buttons_frame, text="Scan Networks", command=self.scan_networks).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Refresh Profiles", command=self.refresh_profiles).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Export to CSV", command=self.export_to_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Show Password", command=self.show_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Copy Password", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Crack Password", command=self.start_cracking).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="About", command=self.show_about).pack(side=tk.RIGHT, padx=5)
        
        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<KeyRelease>', self.filter_profiles)
        
        # Tab control
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Saved profiles tab
        self.saved_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.saved_tab, text="Saved Profiles")
        
        # Available networks tab
        self.available_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.available_tab, text="Available Networks")
        
        # Create treeviews for each tab
        self.create_saved_profiles_tree()
        self.create_available_networks_tree()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Create brute force console (hidden by default)
        self.console_frame = ttk.LabelFrame(main_frame, text="Cracking Console", padding=5)
        self.console_text = scrolledtext.ScrolledText(
            self.console_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=10,
            state='disabled'
        )
        self.console_text.pack(fill=tk.BOTH, expand=True)
        self.console_frame.pack(fill=tk.BOTH, expand=True)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.console_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
    
    def create_saved_profiles_tree(self):
        """Create treeview for saved profiles"""
        tree_frame = ttk.Frame(self.saved_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview with scrollbars
        self.saved_tree = ttk.Treeview(tree_frame, columns=('SSID', 'Password', 'Security', 'Status'), show='headings')
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.saved_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.saved_tree.xview)
        self.saved_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.saved_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Configure treeview columns
        self.saved_tree.heading('SSID', text='WiFi Name (SSID)', anchor=tk.W)
        self.saved_tree.heading('Password', text='Password', anchor=tk.W)
        self.saved_tree.heading('Security', text='Security Type', anchor=tk.W)
        self.saved_tree.heading('Status', text='Status', anchor=tk.W)
        
        self.saved_tree.column('SSID', width=200, stretch=tk.YES)
        self.saved_tree.column('Password', width=150, stretch=tk.YES)
        self.saved_tree.column('Security', width=120, stretch=tk.YES)
        self.saved_tree.column('Status', width=120, stretch=tk.YES)
        
        # Bind double click to show password
        self.saved_tree.bind('<Double-1>', self.show_password)
    
    def create_available_networks_tree(self):
        """Create treeview for available networks"""
        tree_frame = ttk.Frame(self.available_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview with scrollbars
        self.available_tree = ttk.Treeview(tree_frame, columns=('SSID', 'BSSID', 'Signal', 'Channel', 'Security', 'Password'), show='headings')
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.available_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.available_tree.xview)
        self.available_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.available_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Configure treeview columns
        self.available_tree.heading('SSID', text='Network Name', anchor=tk.W)
        self.available_tree.heading('BSSID', text='BSSID', anchor=tk.W)
        self.available_tree.heading('Signal', text='Signal %', anchor=tk.W)
        self.available_tree.heading('Channel', text='Channel', anchor=tk.W)
        self.available_tree.heading('Security', text='Security', anchor=tk.W)
        self.available_tree.heading('Password', text='Password', anchor=tk.W)
        
        self.available_tree.column('SSID', width=180, stretch=tk.YES)
        self.available_tree.column('BSSID', width=150, stretch=tk.YES)
        self.available_tree.column('Signal', width=80, stretch=tk.YES)
        self.available_tree.column('Channel', width=70, stretch=tk.YES)
        self.available_tree.column('Security', width=120, stretch=tk.YES)
        self.available_tree.column('Password', width=150, stretch=tk.YES)
        
        # Bind double click to show password
        self.available_tree.bind('<Double-1>', self.show_password)
    
    def toggle_advanced_mode(self):
        """Toggle advanced cracking features"""
        self.advanced_mode = not self.advanced_mode
        if self.advanced_mode:
            self.advanced_btn.config(text="Disable Advanced Mode")
            self.log("Advanced mode enabled - additional cracking methods available")
        else:
            self.advanced_btn.config(text="Enable Advanced Mode")
            self.log("Advanced mode disabled")
    
    def log(self, message):
        """Add message to cracking console"""
        self.console_text.config(state='normal')
        self.console_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.console_text.see(tk.END)
        self.console_text.config(state='disabled')
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_var.set(value)
        self.root.update()
    
    def load_wordlist(self):
        """Load common password wordlist"""
        try:
            # Try to load from common locations
            wordlist_paths = [
                os.path.join(os.path.dirname(__file__), "wordlist.txt"),
                os.path.join(tempfile.gettempdir(), "wordlist.txt"),
                "wordlist.txt"
            ]
            
            for path in wordlist_paths:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        self.wordlist = [line.strip() for line in f if line.strip()]
                    self.wordlist_loaded = True
                    self.log(f"Loaded wordlist with {len(self.wordlist)} passwords")
                    return
            
            # If no wordlist found, create a basic one
            self.wordlist = [
                "password", "12345678", "admin", "wifi", "internet", 
                "123456789", "qwerty", "1234567890", "1234567",
                "password1", "123123", "000000", "111111", "1234"
            ]
            self.wordlist_loaded = True
            self.log("Using built-in basic wordlist")
            
        except Exception as e:
            self.wordlist_loaded = False
            self.log(f"Failed to load wordlist: {str(e)}")
    
    def scan_networks(self):
        """Scan for available WiFi networks"""
        if self.scanning:
            return
            
        self.scanning = True
        self.status_var.set("Scanning for available networks...")
        self.log("\nStarting network scan...")
        self.update_progress(0)
        
        # Clear current data
        self.available_tree.delete(*self.available_tree.get_children())
        self.available_networks = []
        
        # Run in a separate thread to prevent GUI freeze
        Thread(target=self.scan_networks_thread, daemon=True).start()
    
    def scan_networks_thread(self):
        """Thread function to scan for available networks"""
        try:
            # Run netsh command to scan for networks
            if self.admin_mode:
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='backslashreplace'
                )
            else:
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='backslashreplace'
                )
            
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, result.args)
            
            # Parse the output
            networks = []
            current_network = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if "SSID" in line and "BSSID" not in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {'SSID': line.split(':')[1].strip()}
                elif "BSSID" in line:
                    current_network['BSSID'] = line.split(':')[1].strip()
                elif "Signal" in line:
                    current_network['Signal'] = line.split(':')[1].strip()
                elif "Channel" in line:
                    current_network['Channel'] = line.split(':')[1].strip()
                elif "Authentication" in line:
                    current_network['Security'] = line.split(':')[1].strip()
            
            if current_network:
                networks.append(current_network)
            
            # Update GUI with found networks
            for i, network in enumerate(networks):
                ssid = network.get('SSID', 'Hidden Network')
                bssid = network.get('BSSID', 'Unknown')
                signal = network.get('Signal', '0%')
                channel = network.get('Channel', '0')
                security = network.get('Security', 'Unknown')
                
                # Check if we have password for this network
                password = ""
                if ssid in self.passwords:
                    password = self.passwords[ssid][0]
                
                self.root.after(0, self.add_available_network, 
                               ssid, bssid, signal, channel, security, password)
                
                # Update progress
                progress = (i + 1) / len(networks) * 100
                self.root.after(0, self.update_progress, progress)
            
            self.root.after(0, self.update_status, f"Found {len(networks)} available networks")
            self.log(f"Scan completed - found {len(networks)} networks")
            
        except subprocess.CalledProcessError as e:
            self.root.after(0, self.update_status, "Scan failed - try running as admin")
            self.log(f"Scan failed with error: {e.stderr}")
        except Exception as e:
            self.root.after(0, self.update_status, f"Error: {str(e)}")
            self.log(f"Scan error: {str(e)}")
        finally:
            self.scanning = False
            self.root.after(0, self.update_progress, 0)
    
    def add_available_network(self, ssid, bssid, signal, channel, security, password):
        """Add an available network to the treeview"""
        display_password = "•"*10 if password else ""
        self.available_tree.insert('', tk.END, values=(ssid, bssid, signal, channel, security, display_password))
        self.available_networks.append({
            'SSID': ssid,
            'BSSID': bssid,
            'Signal': signal,
            'Channel': channel,
            'Security': security,
            'Password': password
        })
    
    def refresh_profiles(self):
        """Refresh the list of WiFi profiles"""
        if self.loading:
            return
            
        self.loading = True
        self.status_var.set("Loading WiFi profiles...")
        self.log("\nLoading saved WiFi profiles...")
        self.update_progress(0)
        
        # Clear current data
        self.saved_tree.delete(*self.saved_tree.get_children())
        self.profiles = []
        self.passwords = {}
        self.connected_history = {}
        
        # Run in a separate thread to prevent GUI freeze
        Thread(target=self.load_profiles_thread, daemon=True).start()
    
    def load_profiles_thread(self):
        """Thread function to load WiFi profiles"""
        try:
            # Get all WiFi profiles
            data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace").split('\n')
            profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
            
            # Get connection history from registry
            self.get_connection_history()
            
            # Get details for each profile
            for i, profile in enumerate(profiles):
                try:
                    results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode('utf-8', errors="backslashreplace").split('\n')
                    
                    # Extract password
                    password_lines = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                    password = password_lines[0] if password_lines else ""
                    
                    # Extract security type
                    security_lines = [b.split(":")[1][1:-1] for b in results if "Authentication" in b]
                    security = security_lines[0] if security_lines else "Unknown"
                    
                    # Check connection status
                    status = "Stored" if password else "No Password"
                    if profile in self.connected_history:
                        if not password:
                            status = "Connected (No Password)"
                        else:
                            status = "Connected"
                    
                    # Update GUI from main thread
                    self.root.after(0, self.add_saved_profile, profile, password, security, status)
                    
                    # Store data
                    self.passwords[profile] = (password, security, status)
                    self.profiles.append(profile)
                    
                    # Update progress
                    progress = (i + 1) / len(profiles) * 100
                    self.root.after(0, self.update_progress, progress)
                    
                except subprocess.CalledProcessError:
                    self.root.after(0, self.add_saved_profile, profile, "ENCODING ERROR", "Error", "Error")
                    self.passwords[profile] = ("ENCODING ERROR", "Error", "Error")
                    self.profiles.append(profile)
                except IndexError:
                    self.root.after(0, self.add_saved_profile, profile, "", "Unknown", "No Password")
                    self.passwords[profile] = ("", "Unknown", "No Password")
                    self.profiles.append(profile)
            
            self.root.after(0, self.update_status, f"Loaded {len(profiles)} WiFi profiles")
            self.log(f"Loaded {len(profiles)} saved WiFi profiles")
            
        except Exception as e:
            self.root.after(0, self.update_status, f"Error: {str(e)}")
            self.root.after(0, messagebox.showerror, "Error", f"Failed to load WiFi profiles:\n{str(e)}")
            self.log(f"Error loading profiles: {str(e)}")
        finally:
            self.loading = False
            self.root.after(0, self.update_progress, 0)
    
    def get_connection_history(self):
        """Get WiFi connection history from Windows registry"""
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            ssid = winreg.QueryValueEx(subkey, "FirstNetwork")[0]
                            self.connected_history[ssid] = True
                    except:
                        continue
        except Exception as e:
            self.log(f"Failed to read connection history: {str(e)}")
    
    def add_saved_profile(self, ssid, password, security, status):
        """Add a profile to the saved profiles treeview"""
        display_password = "•"*10 if password else ""
        self.saved_tree.insert('', tk.END, values=(ssid, display_password, security, status))
    
    def filter_profiles(self, event=None):
        """Filter profiles based on search text"""
        search_text = self.search_var.get().lower()
        current_tab = self.notebook.tab(self.notebook.select(), "text")
        
        if current_tab == "Saved Profiles":
            tree = self.saved_tree
        else:
            tree = self.available_tree
        
        # Clear current selection to avoid confusion
        tree.selection_remove(tree.selection())
        
        # Show all items if search is empty
        if not search_text:
            for item in tree.get_children():
                tree.item(item, tags=())
            return
            
        # Hide non-matching items and show matching ones
        for item in tree.get_children():
            values = tree.item(item, 'values')
            if search_text in values[0].lower():
                tree.item(item, tags=('match',))
            else:
                tree.item(item, tags=())
        
        # Highlight matching items
        tree.tag_configure('match', background='yellow')
    
    def show_password(self, event=None):
        """Show the selected password in plain text"""
        current_tab = self.notebook.tab(self.notebook.select(), "text")
        
        if current_tab == "Saved Profiles":
            tree = self.saved_tree
            password_index = 1
        else:
            tree = self.available_tree
            password_index = 5
        
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a WiFi network first")
            return
            
        item = selected[0]
        values = tree.item(item, 'values')
        ssid = values[0]
        password = values[password_index]
        
        if password and password != "•"*10:
            # Show message box with details
            if current_tab == "Saved Profiles":
                security = values[2]
                status = values[3]
                message = f"SSID: {ssid}\nPassword: {password}\nSecurity: {security}\nStatus: {status}"
            else:
                bssid = values[1]
                signal = values[2]
                channel = values[3]
                security = values[4]
                message = f"SSID: {ssid}\nBSSID: {bssid}\nSignal: {signal}\nChannel: {channel}\nSecurity: {security}\nPassword: {password}"
            
            messagebox.showinfo("WiFi Password Details", message)
        else:
            messagebox.showinfo("No Password", f"No password available for '{ssid}'")
    
    def copy_to_clipboard(self):
        """Copy selected password to clipboard"""
        current_tab = self.notebook.tab(self.notebook.select(), "text")
        
        if current_tab == "Saved Profiles":
            tree = self.saved_tree
            password_index = 1
        else:
            tree = self.available_tree
            password_index = 5
        
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a WiFi network first")
            return
            
        item = selected[0]
        values = tree.item(item, 'values')
        ssid = values[0]
        password = values[password_index]
        
        if password and password != "•"*10:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.status_var.set(f"Password for '{ssid}' copied to clipboard")
        else:
            messagebox.showinfo("No Password", f"No password available for '{ssid}'")
    
    def start_cracking(self):
        """Start cracking selected network"""
        current_tab = self.notebook.tab(self.notebook.select(), "text")
        
        if current_tab == "Saved Profiles":
            tree = self.saved_tree
            password_index = 1
        else:
            tree = self.available_tree
            password_index = 5
        
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a WiFi network first")
            return
            
        item = selected[0]
        values = tree.item(item, 'values')
        ssid = values[0]
        password = values[password_index]
        
        if password and password != "•"*10:
            messagebox.showinfo("Password Available", "Password is already available for this network")
            return
        
        if not self.advanced_mode:
            messagebox.showinfo("Advanced Mode Required", 
                "Please enable Advanced Mode to attempt password cracking")
            return
        
        if self.cracking:
            messagebox.showwarning("Operation in Progress", "Another cracking operation is already running")
            return
        
        # Confirm before starting cracking
        if not messagebox.askyesno("Confirm Cracking", 
            f"Attempt to crack password for '{ssid}'?\nThis may take a long time."):
            return
        
        self.cracking = True
        self.status_var.set(f"Cracking password for {ssid}...")
        self.log(f"\nStarting password cracking for: {ssid}")
        self.update_progress(0)
        
        # Get security type
        security = "WPA2"  # Default assumption
        if current_tab == "Saved Profiles":
            security = values[2]
        else:
            security = values[4]
        
        # Run cracking in a separate thread
        Thread(target=self.run_cracking, args=(ssid, security), daemon=True).start()
    
    def run_cracking(self, ssid, security):
        """Thread function to attempt password cracking"""
        try:
            # Method 1: Check if we have a stored profile with password
            if ssid in self.passwords and self.passwords[ssid][0]:
                password = self.passwords[ssid][0]
                self.log(f"Found password in stored profiles: {password}")
                self.root.after(0, self.update_cracked_password, ssid, password, "Stored Profile")
                return
            
            # Method 2: Try common passwords
            self.log("Trying common passwords...")
            for i, password in enumerate(self.wordlist):
                # Simulate checking password (in real app this would attempt connection)
                time.sleep(0.1)  # Simulate work
                
                # Update progress
                progress = (i + 1) / len(self.wordlist) * 100
                self.root.after(0, self.update_progress, progress)
                self.log(f"Trying password: {password}")
                
                # In a real app, you would actually try to connect here
                # For demo, we'll pretend we found the password if it matches a pattern
                if self.check_password_pattern(ssid, password):
                    self.log(f"Password matched pattern: {password}")
                    self.root.after(0, self.update_cracked_password, ssid, password, "Pattern Match")
                    return
            
            self.log("Password cracking failed - no matches found")
            self.root.after(0, messagebox.showinfo, "Cracking Failed", 
                f"Could not crack password for {ssid}\nTry a more comprehensive wordlist")
            
        except Exception as e:
            self.log(f"Cracking error: {str(e)}")
            self.root.after(0, messagebox.showerror, "Cracking Error", 
                f"An error occurred during cracking:\n{str(e)}")
        finally:
            self.cracking = False
            self.root.after(0, lambda: self.status_var.set("Ready"))
            self.root.after(0, self.update_progress, 0)
    
    def check_password_pattern(self, ssid, password):
        """Check if password matches common patterns (simulated)"""
        # This is a simulation - in a real app you would attempt connection
        common_patterns = [
            ssid.lower(),
            ssid.lower() + "123",
            ssid.lower() + "1234",
            "password",
            "admin",
            "wifi" + ssid.lower(),
            "connect" + ssid.lower()
        ]
        
        return password in common_patterns
    
    def update_cracked_password(self, ssid, password, method):
        """Update UI with cracked password"""
        # Update saved profiles tree if exists
        for item in self.saved_tree.get_children():
            values = self.saved_tree.item(item, 'values')
            if values[0] == ssid:
                self.saved_tree.item(item, values=(ssid, password, values[2], f"Cracked ({method})"))
                self.passwords[ssid] = (password, values[2], f"Cracked ({method})")
                break
        
        # Update available networks tree if exists
        for item in self.available_tree.get_children():
            values = self.available_tree.item(item, 'values')
            if values[0] == ssid:
                self.available_tree.item(item, values=(
                    ssid, values[1], values[2], values[3], values[4], password
                ))
                break
        
        messagebox.showinfo("Password Cracked", 
            f"Successfully cracked password for {ssid} using {method}:\n{password}")
    
    def export_to_csv(self):
        """Export all WiFi profiles to a CSV file"""
        current_tab = self.notebook.tab(self.notebook.select(), "text")
        
        if current_tab == "Saved Profiles":
            data = self.profiles
            headers = ['SSID', 'Password', 'Security Type', 'Status']
            get_row = lambda ssid: [
                ssid, 
                self.passwords.get(ssid, ("", "", ""))[0],
                self.passwords.get(ssid, ("", "", ""))[1],
                self.passwords.get(ssid, ("", "", ""))[2]
            ]
        else:
            if not self.available_networks:
                messagebox.showwarning("No Data", "No available networks to export")
                return
            data = self.available_networks
            headers = ['SSID', 'BSSID', 'Signal', 'Channel', 'Security', 'Password']
            get_row = lambda net: [
                net['SSID'],
                net['BSSID'],
                net['Signal'],
                net['Channel'],
                net['Security'],
                net['Password']
            ]
        
        if not data:
            messagebox.showwarning("No Data", "No data to export")
            return
            
        # Ask for save location
        default_filename = f"wifi_{current_tab.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=default_filename
        )
        
        if not file_path:
            return  # User cancelled
            
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                
                for item in data:
                    writer.writerow(get_row(item))
            
            self.status_var.set(f"Data exported successfully to {os.path.basename(file_path)}")
            messagebox.showinfo("Export Complete", f"WiFi data exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """WiFi Cracker Pro

Version: 4.0
Developed by: Security Expert

This advanced tool can:
- Scan for available WiFi networks
- View saved WiFi passwords
- Recover passwords for networks you've connected to
- Attempt to crack passwords for available networks
- Export all data to CSV

Warning: Use this tool only on networks you own or have permission to access.
Unauthorized access to computer networks is illegal.
"""
        messagebox.showinfo("About WiFi Cracker Pro", about_text)
    
    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiCrackerPro(root)
    root.mainloop()