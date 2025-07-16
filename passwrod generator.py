import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("400x400")
        self.root.resizable(False, False)
        
        # Variables
        self.password_var = tk.StringVar()
        self.length_var = tk.IntVar(value=12)
        
        # Character type options
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True) 
        self.symbols_var = tk.BooleanVar(value=True)
        
        # Create UI
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Password Generator",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=10)
        
        # Password display
        pass_frame = ttk.Frame(main_frame)
        pass_frame.pack(fill=tk.X, pady=10)
        
        self.password_entry = ttk.Entry(
            pass_frame,
            textvariable=self.password_var,
            font=("Arial", 12),
            state="readonly",
            width=25
        )
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        # Copy button
        copy_btn = ttk.Button(
            pass_frame,
            text="Copy",
            command=self.copy_password,
            width=8
        )
        copy_btn.pack(side=tk.LEFT)
        
        # Length control
        length_frame = ttk.Frame(main_frame)
        length_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(
            length_frame,
            text="Password Length:",
            font=("Arial", 10)
        ).pack(side=tk.LEFT)
        
        self.length_scale = ttk.Scale(
            length_frame,
            from_=8,
            to=32,
            variable=self.length_var,
            command=lambda e: self.update_length_display()
        )
        self.length_scale.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.length_display = ttk.Label(
            length_frame,
            textvariable=self.length_var,
            width=3
        )
        self.length_display.pack(side=tk.LEFT)
        
        # Character types
        char_frame = ttk.LabelFrame(
            main_frame,
            text="Character Types",
            padding=10
        )
        char_frame.pack(fill=tk.X, pady=10)
        
        ttk.Checkbutton(
            char_frame,
            text="Uppercase (A-Z)",
            variable=self.uppercase_var
        ).pack(anchor=tk.W)
        
        ttk.Checkbutton(
            char_frame,
            text="Lowercase (a-z)",
            variable=self.lowercase_var
        ).pack(anchor=tk.W)
        
        ttk.Checkbutton(
            char_frame,
            text="Digits (0-9)",
            variable=self.digits_var
        ).pack(anchor=tk.W)
        
        ttk.Checkbutton(
            char_frame,
            text="Symbols (!@#$%^&*)",
            variable=self.symbols_var
        ).pack(anchor=tk.W)
        
        # Strength meter
        strength_frame = ttk.Frame(main_frame)
        strength_frame.pack(fill=tk.X, pady=5)
        
        self.strength_bar = ttk.Progressbar(
            strength_frame,
            length=200,
            mode='determinate'
        )
        self.strength_bar.pack(side=tk.LEFT)
        
        self.strength_label = ttk.Label(
            strength_frame,
            text="",
            width=10
        )
        self.strength_label.pack(side=tk.LEFT, padx=10)
        
        # Generate button
        generate_btn = ttk.Button(
            main_frame,
            text="Generate Password",
            command=self.generate_password,
            width=20
        )
        generate_btn.pack(pady=10)
        
    def update_length_display(self):
        # Round the slider value to nearest integer
        length = round(self.length_var.get())
        self.length_var.set(length)
        return length
        
    def generate_password(self):
        # Check at least one option is selected
        if not any([
            self.uppercase_var.get(),
            self.lowercase_var.get(),
            self.digits_var.get(),
            self.symbols_var.get()
        ]):
            messagebox.showerror(
                "Error",
                "Please select at least one character type"
            )
            return
            
        # Build character pool based on selections
        characters = []
        
        if self.uppercase_var.get():
            characters += list(string.ascii_uppercase)
        if self.lowercase_var.get():
            characters += list(string.ascii_lowercase)
        if self.digits_var.get():
            characters += list(string.digits)
        if self.symbols_var.get():
            characters += list("!@#$%^&*")
            
        # Generate password
        length = self.update_length_display()
        password = ''.join(random.choices(characters, k=length))
        self.password_var.set(password)
        
        # Calculate and display strength
        self.show_strength(password)
        
    def show_strength(self, password):
        # Simple strength calculation
        strength = 0
        
        # Length score (max 40 points)
        strength += min(len(password) * 2, 40)
        
        # Character variety score (max 45 points)
        checks = [
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(c in "!@#$%^&*" for c in password)
        ]
        strength += sum(checks) * 15  # 15 points per type
        
        # Cap at 100
        strength = min(strength, 100)
        
        # Update display
        self.strength_bar['value'] = strength
        
        if strength < 40:
            text = "Weak"
            color = "red"
        elif strength < 70:
            text = "Medium" 
            color = "orange"
        else:
            text = "Strong"
            color = "green"
            
        self.strength_label.config(text=text, foreground=color)
        
    def copy_password(self):
        if self.password_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.password_var.get())
            messagebox.showinfo(
                "Copied",
                "Password copied to clipboard!"
            )
        else:
            messagebox.showerror(
                "Error",
                "No password generated yet!"
            )

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()
