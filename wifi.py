import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
from threading import Thread
import os
import csv
from datetime import datetime

class WiFiPasswordViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced WiFi Password Viewer")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.root.minsize(800, 500)
        
        # Initialize attributes
        self.loading = False
        self.profiles = []
        self.passwords = {}
        
        # Set application icon (replace with actual icon path if available)
        try:
            self.root.iconbitmap(default='wifi.ico')  # Provide your icon file
        except:
            pass
        
        self.create_widgets()
        self.center_window()
        self.refresh_profiles()
    
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
        
        ttk.Label(header_frame, text="WiFi Password Viewer", font=('Helvetica', 16, 'bold')).pack(side=tk.LEFT)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(buttons_frame, text="Refresh", command=self.refresh_profiles).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Export to CSV", command=self.export_to_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Show Password", command=self.show_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="About", command=self.show_about).pack(side=tk.RIGHT, padx=5)
        
        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<KeyRelease>', self.filter_profiles)
        
        # Treeview frame
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview with scrollbars
        self.tree = ttk.Treeview(tree_frame, columns=('SSID', 'Password', 'Security'), show='headings')
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Configure treeview columns
        self.tree.heading('SSID', text='WiFi Name (SSID)', anchor=tk.W)
        self.tree.heading('Password', text='Password', anchor=tk.W)
        self.tree.heading('Security', text='Security Type', anchor=tk.W)
        
        self.tree.column('SSID', width=250, stretch=tk.YES)
        self.tree.column('Password', width=200, stretch=tk.YES)
        self.tree.column('Security', width=150, stretch=tk.YES)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Bind double click to show password
        self.tree.bind('<Double-1>', self.show_password)
    
    def refresh_profiles(self):
        """Refresh the list of WiFi profiles"""
        if self.loading:
            return
            
        self.loading = True
        self.status_var.set("Loading WiFi profiles...")
        self.root.update()
        
        # Clear current data
        self.tree.delete(*self.tree.get_children())
        self.profiles = []
        self.passwords = {}
        
        # Run in a separate thread to prevent GUI freeze
        Thread(target=self.load_profiles_thread, daemon=True).start()
    
    def load_profiles_thread(self):
        """Thread function to load WiFi profiles"""
        try:
            # Get all WiFi profiles
            data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace").split('\n')
            profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
            
            # Get details for each profile
            for profile in profiles:
                try:
                    results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode('utf-8', errors="backslashreplace").split('\n')
                    
                    # Extract password
                    password_lines = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                    password = password_lines[0] if password_lines else ""
                    
                    # Extract security type
                    security_lines = [b.split(":")[1][1:-1] for b in results if "Authentication" in b]
                    security = security_lines[0] if security_lines else "Unknown"
                    
                    # Update GUI from main thread
                    self.root.after(0, self.add_profile_to_tree, profile, password, security)
                    
                    # Store data
                    self.passwords[profile] = (password, security)
                    self.profiles.append(profile)
                    
                except subprocess.CalledProcessError:
                    self.root.after(0, self.add_profile_to_tree, profile, "ENCODING ERROR", "Error")
                    self.passwords[profile] = ("ENCODING ERROR", "Error")
                    self.profiles.append(profile)
                except IndexError:
                    self.root.after(0, self.add_profile_to_tree, profile, "", "Unknown")
                    self.passwords[profile] = ("", "Unknown")
                    self.profiles.append(profile)
            
            self.root.after(0, self.update_status, f"Loaded {len(profiles)} WiFi profiles")
            
        except Exception as e:
            self.root.after(0, self.update_status, f"Error: {str(e)}")
            self.root.after(0, messagebox.showerror, "Error", f"Failed to load WiFi profiles:\n{str(e)}")
        finally:
            self.root.after(0, lambda: setattr(self, 'loading', False))
    
    def add_profile_to_tree(self, ssid, password, security):
        """Add a profile to the treeview"""
        self.tree.insert('', tk.END, values=(ssid, "•"*10 if password else "", security))
    
    def filter_profiles(self, event=None):
        """Filter profiles based on search text"""
        search_text = self.search_var.get().lower()
        
        # Clear current selection to avoid confusion
        self.tree.selection_remove(self.tree.selection())
        
        # Show all items if search is empty
        if not search_text:
            for item in self.tree.get_children():
                self.tree.item(item, tags=())
            return
            
        # Hide non-matching items and show matching ones
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if search_text in values[0].lower():
                self.tree.item(item, tags=('match',))
            else:
                self.tree.item(item, tags=())
        
        # Highlight matching items
        self.tree.tag_configure('match', background='yellow')
    
    def show_password(self, event=None):
        """Show the selected password in plain text"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a WiFi network first")
            return
            
        item = selected[0]
        values = self.tree.item(item, 'values')
        ssid = values[0]
        
        if ssid in self.passwords:
            password, security = self.passwords[ssid]
            if password:
                # Update treeview to show password
                self.tree.item(item, values=(ssid, password, security))
                
                # Show message box with details
                message = f"SSID: {ssid}\nPassword: {password}\nSecurity: {security}"
                messagebox.showinfo("WiFi Password Details", message)
            else:
                messagebox.showinfo("No Password", f"The network '{ssid}' has no password stored")
        else:
            messagebox.showerror("Error", "Failed to retrieve password for selected network")
    
    def copy_to_clipboard(self):
        """Copy selected password to clipboard"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a WiFi network first")
            return
            
        item = selected[0]
        values = self.tree.item(item, 'values')
        ssid = values[0]
        
        if ssid in self.passwords:
            password, _ = self.passwords[ssid]
            if password:
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                self.status_var.set(f"Password for '{ssid}' copied to clipboard")
            else:
                messagebox.showinfo("No Password", f"The network '{ssid}' has no password stored")
        else:
            messagebox.showerror("Error", "Failed to retrieve password for selected network")
    
    def export_to_csv(self):
        """Export all WiFi profiles to a CSV file"""
        if not self.profiles:
            messagebox.showwarning("No Data", "No WiFi profiles to export")
            return
            
        # Ask for save location
        default_filename = f"wifi_passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
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
                writer.writerow(['SSID', 'Password', 'Security Type'])
                
                for ssid in self.profiles:
                    password, security = self.passwords.get(ssid, ("", "Unknown"))
                    writer.writerow([ssid, password, security])
            
            self.status_var.set(f"Data exported successfully to {os.path.basename(file_path)}")
            messagebox.showinfo("Export Complete", f"WiFi passwords exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Advanced WiFi Password Viewer

Version: 2.0
Developed by: Your Name

This tool displays all WiFi passwords stored on your Windows computer.

Features:
- View all saved WiFi networks and their passwords
- Search/filter networks
- Copy passwords to clipboard
- Export data to CSV
- Secure password display (hidden by default)

Note: This tool only works on Windows and requires administrator privileges to access WiFi passwords.
"""
        messagebox.showinfo("About WiFi Password Viewer", about_text)
    
    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiPasswordViewer(root)
    root.mainloop()