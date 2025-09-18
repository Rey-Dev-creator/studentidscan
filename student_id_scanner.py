import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import winsound
import json
import os
import threading
import time

# File constants
STUDENTS_FILE = "students.json"
LOG_FILE = "scan_logs.txt"
ADMIN_PASSWORD = "admin123"
ADMIN_LOG_FILE = "admin_logs.txt"
CHAT_FILE = "chat_messages.json"

# Global chat variables
chat_windows = []
current_student = None

def load_students_list():
    if not os.path.exists(STUDENTS_FILE):
        with open(STUDENTS_FILE, "w") as f:
            json.dump([], f)
    with open(STUDENTS_FILE, "r") as f:
        return json.load(f)

def save_students_list(students):
    with open(STUDENTS_FILE, "w") as f:
        json.dump(students, f, indent=2)

def load_students():
    """Load students as a dictionary keyed by student ID"""
    students_list = load_students_list()
    return {s["id"]: s for s in students_list}

def save_student(student):
    students = load_students_list()
    if any(s["id"] == student["id"] for s in students):
        return False
    student["logs"] = [
        f"{datetime.now()} | CREATED | Name: {student['name']} | Program: {student['program']} | Expiry: {student['expiry']}"
    ]
    students.append(student)
    save_students_list(students)
    with open(LOG_FILE, "a") as logf:
        logf.write(f"{datetime.now()} | CREATED | ID: {student['id']} | Name: {student['name']} | Program: {student['program']} | Expiry: {student['expiry']}\n")
    return True

def log_scan(student_id, result, info=""):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | ID: {student_id} | Result: {result} | {info}\n")
    students = load_students_list()
    updated = False
    for s in students:
        if s["id"] == student_id:
            if "logs" not in s:
                s["logs"] = []
            s["logs"].append(f"{datetime.now()} | SCAN | Result: {result} | {info}")
            updated = True
            break
    if updated:
        save_students_list(students)

def log_admin_action(action):
    with open(ADMIN_LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {action}\n")

# Chat System Functions
def load_chat_messages():
    """Load chat messages from file"""
    if not os.path.exists(CHAT_FILE):
        with open(CHAT_FILE, "w") as f:
            json.dump([], f)
        return []
    
    try:
        with open(CHAT_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def save_chat_message(message_data):
    """Save a new chat message"""
    messages = load_chat_messages()
    messages.append(message_data)
    
    # Keep only last 1000 messages to prevent file from growing too large
    if len(messages) > 1000:
        messages = messages[-1000:]
    
    with open(CHAT_FILE, "w") as f:
        json.dump(messages, f, indent=2)

def validate_message(message):
    """Validate chat message input"""
    if not message or not message.strip():
        return False, "Message cannot be empty"
    
    if len(message.strip()) > 500:
        return False, "Message too long (max 500 characters)"
    
    # Basic content filtering
    prohibited_words = ["admin", "password", "hack", "delete"]
    message_lower = message.lower()
    for word in prohibited_words:
        if word in message_lower:
            return False, f"Message contains prohibited content: '{word}'"
    
    return True, ""

def format_chat_message(message_data):
    """Format message for display"""
    timestamp = datetime.fromisoformat(message_data['timestamp']).strftime("%H:%M:%S")
    return f"[{timestamp}] {message_data['student_name']} ({message_data['student_id']}): {message_data['message']}\n"

def open_student_chat():
    """Open chat window for verified students only"""
    global current_student
    
    if not current_student:
        messagebox.showerror("Access Denied", "Please scan your student ID first to access chat.")
        return
    
    # Check if student is verified and not expired
    students = load_students()
    if current_student['id'] not in students:
        messagebox.showerror("Access Denied", "Student not found in system.")
        return
    
    student_data = students[current_student['id']]
    
    # Check if student is verified
    if not student_data.get("verified", False):
        messagebox.showerror("Access Denied", "Only verified students can access chat.")
        return
    
    # Check if student ID is not expired
    expiry_date = datetime.strptime(student_data["expiry"], "%Y-%m-%d")
    if expiry_date < datetime.now():
        messagebox.showerror("Access Denied", "Expired student IDs cannot access chat.")
        return
    
    # Create chat window
    create_chat_window(current_student)

def create_chat_window(student_info):
    """Create the chat interface window"""
    global chat_windows
    
    # Check if chat window already exists for this student
    for chat_win in chat_windows:
        if chat_win.winfo_exists():
            chat_win.lift()
            chat_win.focus_set()
            return
    
    chat_win = tk.Toplevel(root)
    chat_win.title(f"Student Chat - {student_info['name']}")
    chat_win.configure(bg="#f0f4f7")
    chat_win.geometry("600x500")
    
    # Add to chat windows list
    chat_windows.append(chat_win)
    
    # Header
    header_frame = tk.Frame(chat_win, bg="#1976d2", height=50)
    header_frame.pack(fill="x")
    header_frame.pack_propagate(False)
    
    tk.Label(
        header_frame,
        text=f"💬 Student Global Chat - Welcome {student_info['name']}!",
        font=("Arial", 12, "bold"),
        bg="#1976d2",
        fg="white"
    ).pack(expand=True)
    
    # Chat display area
    chat_frame = tk.Frame(chat_win, bg="#f0f4f7")
    chat_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    tk.Label(chat_frame, text="Messages:", font=("Arial", 10, "bold"), bg="#f0f4f7").pack(anchor="w")
    
    # Scrollable text area for messages
    chat_display = scrolledtext.ScrolledText(
        chat_frame,
        height=20,
        width=70,
        font=("Arial", 9),
        bg="#ffffff",
        fg="#333333",
        state="disabled",
        wrap="word"
    )
    chat_display.pack(fill="both", expand=True, pady=(5, 10))
    
    # Message input area
    input_frame = tk.Frame(chat_frame, bg="#f0f4f7")
    input_frame.pack(fill="x", pady=(0, 10))
    
    tk.Label(input_frame, text="Your message:", font=("Arial", 10), bg="#f0f4f7").pack(anchor="w")
    
    # Message entry with character counter
    entry_frame = tk.Frame(input_frame, bg="#f0f4f7")
    entry_frame.pack(fill="x", pady=(5, 0))
    
    message_var = tk.StringVar()
    message_entry = tk.Entry(
        entry_frame,
        textvariable=message_var,
        font=("Arial", 10),
        width=50
    )
    message_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
    
    # Character counter
    char_counter = tk.Label(entry_frame, text="0/500", font=("Arial", 8), bg="#f0f4f7", fg="#666")
    char_counter.pack(side="right")
    
    def update_char_counter(*args):
        count = len(message_var.get())
        char_counter.config(text=f"{count}/500")
        if count > 500:
            char_counter.config(fg="red")
        else:
            char_counter.config(fg="#666")
    
    message_var.trace_add("write", update_char_counter)
    
    # Send button
    def send_message():
        message = message_var.get().strip()
        
        # Validate message
        is_valid, error_msg = validate_message(message)
        if not is_valid:
            messagebox.showerror("Invalid Message", error_msg)
            return
        
        # Create message data
        message_data = {
            "timestamp": datetime.now().isoformat(),
            "student_id": student_info['id'],
            "student_name": student_info['name'],
            "student_program": student_info['program'],
            "message": message
        }
        
        # Save message
        save_chat_message(message_data)
        
        # Clear input
        message_var.set("")
        
        # Update all chat windows
        update_all_chat_displays()
        
        # Log chat activity
        log_scan(student_info['id'], "CHAT_MESSAGE", f"Sent message: {message[:50]}...")
    
    send_btn = tk.Button(
        input_frame,
        text="Send",
        command=send_message,
        bg="#4caf50",
        fg="white",
        font=("Arial", 10, "bold"),
        width=8
    )
    send_btn.pack(side="right", padx=(5, 0))
    
    # Bind Enter key to send message
    message_entry.bind("<Return>", lambda e: send_message())
    
    # Control buttons
    control_frame = tk.Frame(chat_frame, bg="#f0f4f7")
    control_frame.pack(fill="x")
    
    tk.Button(
        control_frame,
        text="Refresh",
        command=lambda: update_chat_display(chat_display),
        bg="#2196f3",
        fg="white",
        font=("Arial", 9),
        width=10
    ).pack(side="left", padx=(0, 5))
    
    tk.Button(
        control_frame,
        text="Clear Display",
        command=lambda: clear_chat_display(chat_display),
        bg="#ff9800",
        fg="white",
        font=("Arial", 9),
        width=12
    ).pack(side="left", padx=(0, 5))
    
    # Online users info
    online_label = tk.Label(
        control_frame,
        text="💡 Tip: Only verified students can chat",
        font=("Arial", 8),
        bg="#f0f4f7",
        fg="#666"
    )
    online_label.pack(side="right")
    
    # Store references for updates
    chat_win.chat_display = chat_display
    chat_win.student_info = student_info
    
    # Load existing messages
    update_chat_display(chat_display)
    
    # Start auto-refresh
    start_chat_auto_refresh(chat_win)
    
    # Focus on message entry
    message_entry.focus_set()
    
    # Handle window closing
    def on_closing():
        if chat_win in chat_windows:
            chat_windows.remove(chat_win)
        chat_win.destroy()
    
    chat_win.protocol("WM_DELETE_WINDOW", on_closing)

def update_chat_display(chat_display):
    """Update chat display with latest messages"""
    messages = load_chat_messages()
    
    chat_display.config(state="normal")
    chat_display.delete(1.0, tk.END)
    
    # Display last 50 messages
    recent_messages = messages[-50:] if len(messages) > 50 else messages
    
    for message_data in recent_messages:
        formatted_message = format_chat_message(message_data)
        chat_display.insert(tk.END, formatted_message)
    
    chat_display.config(state="disabled")
    chat_display.see(tk.END)  # Scroll to bottom

def clear_chat_display(chat_display):
    """Clear the chat display (local only)"""
    chat_display.config(state="normal")
    chat_display.delete(1.0, tk.END)
    chat_display.insert(tk.END, "Chat display cleared (messages still saved)\n")
    chat_display.config(state="disabled")

def update_all_chat_displays():
    """Update all open chat windows"""
    global chat_windows
    active_windows = []
    
    for chat_win in chat_windows:
        try:
            if chat_win.winfo_exists():
                update_chat_display(chat_win.chat_display)
                active_windows.append(chat_win)
        except tk.TclError:
            # Window was destroyed
            pass
    
    chat_windows = active_windows

def start_chat_auto_refresh(chat_win):
    """Start auto-refresh for chat window"""
    def auto_refresh():
        try:
            if chat_win.winfo_exists():
                update_chat_display(chat_win.chat_display)
                # Schedule next refresh in 5 seconds
                chat_win.after(5000, auto_refresh)
        except tk.TclError:
            # Window was destroyed
            pass
    
    # Start auto-refresh after 5 seconds
    chat_win.after(5000, auto_refresh)

# Enhanced check_id function to set current student
def check_id():
    global current_student
    student_id = entry_id.get().strip()
    info_text.config(state="normal")
    info_text.delete(1.0, tk.END)
    students = load_students()
    global last_scanned_student
    last_scanned_student = None
    current_student = None

    if student_id in students:
        student = students[student_id]
        last_scanned_student = student
        current_student = student  # Set current student for chat access
        
        expiry_date = datetime.strptime(student["expiry"], "%Y-%m-%d")
        expired = expiry_date < datetime.now()
        verified = "Verified" if student.get("verified") else "Not Verified"
        info = (
            f"Student ID: {student_id}\n"
            f"Name: {student['name']}\n"
            f"Program: {student['program']}\n"
            f"Expiry Date: {student['expiry']}\n"
            f"Status: {'Expired' if expired else 'Active'}\n"
            f"Verification: {verified}"
        )
        info_text.insert(tk.END, info)
        info_text.config(state="disabled")
        log_scan(student_id, "VALID", f"{'Expired' if expired else 'Active'} | {verified}")
        
        if expired:
            messagebox.showwarning("Expired", "This student ID is expired!")
        else:
            messagebox.showinfo("Access Granted", "Scanned! You can now access student features.")
        
        if not student.get("verified"):
            verify_notify_label.config(text="This student is not verified. Click 'Verify' to verify.", fg="red")
        else:
            verify_notify_label.config(text="This student is verified. Chat access available!", fg="green")
            
        # Enable chat button for verified, active students
        if student.get("verified") and not expired:
            chat_button.config(state="normal", bg="#9c27b0")
        else:
            chat_button.config(state="disabled", bg="#cccccc")
    else:
        info_text.insert(tk.END, "ERROR: Invalid Student ID!\n")
        info_text.config(state="disabled")
        log_scan(student_id, "INVALID")
        winsound.Beep(1000, 500)
        verify_notify_label.config(text="")
        chat_button.config(state="disabled", bg="#cccccc")

def verify_student():
    global last_scanned_student, current_student
    if not last_scanned_student:
        messagebox.showerror("Verify", "No student scanned to verify.")
        return
    students = load_students_list()
    for s in students:
        if s["id"] == last_scanned_student["id"]:
            s["verified"] = True
            if "logs" not in s:
                s["logs"] = []
            s["logs"].append(f"{datetime.now()} | VERIFIED")
            break
    save_students_list(students)
    messagebox.showinfo("Verified", f"Student {last_scanned_student['name']} has been verified!")
    verify_notify_label.config(text="This student is verified. Chat access available!", fg="green")
    
    # Update current student verification status
    if current_student and current_student["id"] == last_scanned_student["id"]:
        current_student["verified"] = True
        # Enable chat button
        expiry_date = datetime.strptime(current_student["expiry"], "%Y-%m-%d")
        if expiry_date >= datetime.now():
            chat_button.config(state="normal", bg="#9c27b0")

def open_create_student():
    def on_sid_entry(*args):
        value = sid_var.get()
        if not value.isdigit():
            sid_var.set(''.join(filter(str.isdigit, value))[:8])
        elif len(value) > 8:
            sid_var.set(value[:8])

    def save_new_student():
        sid = entry_sid.get().strip()
        name = entry_name.get().strip()
        program = entry_program.get().strip()
        expiry = entry_expiry.get().strip()

        if not sid or not name or not program or not expiry:
            messagebox.showerror("Error", "All fields are required.")
            return
        if not (sid.isdigit() and len(sid) == 8):
            messagebox.showerror("Error", "Student ID must be exactly 8 digits.")
            return
        try:
            datetime.strptime(expiry, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Error", "Expiry date must be YYYY-MM-DD.")
            return
        
        student = {"id": sid, "name": name, "program": program, "expiry": expiry}
        if save_student(student):
            messagebox.showinfo("Success", "Student created successfully!")
            create_win.destroy()
        else:
            messagebox.showerror("Error", "Student ID already exists.")

    create_win = tk.Toplevel(root)
    create_win.title("Create Student")
    create_win.configure(bg="#f0f4f7")

    tk.Label(create_win, text="Student ID:", bg="#f0f4f7", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=3, padx=3)
    sid_var = tk.StringVar()
    sid_var.trace_add("write", on_sid_entry)
    entry_sid = tk.Entry(create_win, textvariable=sid_var, font=("Arial", 10))
    entry_sid.grid(row=0, column=1, pady=3, padx=3)

    tk.Label(create_win, text="Name:", bg="#f0f4f7", font=("Arial", 10)).grid(row=1, column=0, sticky="e", pady=3, padx=3)
    entry_name = tk.Entry(create_win, font=("Arial", 10))
    entry_name.grid(row=1, column=1, pady=3, padx=3)

    tk.Label(create_win, text="Program:", bg="#f0f4f7", font=("Arial", 10)).grid(row=2, column=0, sticky="e", pady=3, padx=3)
    entry_program = tk.Entry(create_win, font=("Arial", 10))
    entry_program.grid(row=2, column=1, pady=3, padx=3)

    tk.Label(create_win, text="Expiry (YYYY-MM-DD):", bg="#f0f4f7", font=("Arial", 10)).grid(row=3, column=0, sticky="e", pady=3, padx=3)
    entry_expiry = tk.Entry(create_win, font=("Arial", 10))
    entry_expiry.grid(row=3, column=1, pady=3, padx=3)

    tk.Button(create_win, text="Save", command=save_new_student, bg="#4caf50", fg="white", font=("Arial", 10, "bold")).grid(row=4, column=0, columnspan=2, pady=10)

def list_students():
    students = load_students_list()
    list_win = tk.Toplevel(root)
    list_win.title("List of Students")
    list_win.configure(bg="#f0f4f7")
    tk.Label(list_win, text="Registered Students (Real-Time)", font=("Arial", 12, "bold"), bg="#f0f4f7").pack(pady=5)
    listbox = tk.Listbox(list_win, width=90, font=("Consolas", 10))
    listbox.pack(padx=10, pady=10, fill="both", expand=True)
    
    if not students:
        listbox.insert(tk.END, "No students found.")
    else:
        for s in students:
            verified = "Verified" if s.get("verified") else "Not Verified"
            status = "Expired" if datetime.strptime(s["expiry"], "%Y-%m-%d") < datetime.now() else "Active"
            listbox.insert(
                tk.END,
                f"ID: {s['id']} | Name: {s['name']} | Program: {s['program']} | Expiry: {s['expiry']} | Status: {status} | {verified}"
            )
            
            def on_select(event):
                selection = event.widget.curselection()
                if selection:
                    idx = selection[0]
                    student = students[idx]
                    logs = student.get("logs", [])
                    logs_win = tk.Toplevel(list_win)
                    logs_win.title(f"Logs for {student['name']} ({student['id']})")
                    logs_win.configure(bg="#f0f4f7")
                    tk.Label(logs_win, text=f"Logs for {student['name']} ({student['id']})", font=("Arial", 11, "bold"), bg="#f0f4f7").pack(pady=5)
                    logs_text = tk.Text(logs_win, width=80, height=15, font=("Consolas", 10), bg="#f5f5f5")
                    logs_text.pack(padx=10, pady=10)
                    if logs:
                        for log in logs:
                            logs_text.insert(tk.END, log + "\n")
                    else:
                        logs_text.insert(tk.END, "No logs for this student.\n")
                    logs_text.config(state="disabled")
            
            listbox.bind("<Double-Button-1>", on_select)

def open_remove_student_section():
    def check_admin():
        password = entry_pass.get()
        if password == ADMIN_PASSWORD:
            admin_win.destroy()
            show_remove_student_window()
        else:
            messagebox.showerror("Access Denied", "Incorrect admin password.")
            log_admin_action("FAILED ADMIN LOGIN ATTEMPT")

    admin_win = tk.Toplevel(root)
    admin_win.title("Admin Login")
    admin_win.configure(bg="#f0f4f7")
    tk.Label(admin_win, text="Enter Admin Password:", bg="#f0f4f7", font=("Arial", 10)).pack(padx=10, pady=10)
    entry_pass = tk.Entry(admin_win, show="*", font=("Arial", 10))
    entry_pass.pack(padx=10, pady=5)
    tk.Button(admin_win, text="Login", command=check_admin, bg="#1976d2", fg="white", font=("Arial", 10, "bold")).pack(pady=10)
    entry_pass.focus_set()

def show_remove_student_window():
    students = load_students_list()
    remove_win = tk.Toplevel(root)
    remove_win.title("Remove Student")
    remove_win.configure(bg="#f0f4f7")
    tk.Label(remove_win, text="Select Student to Remove", font=("Arial", 12, "bold"), bg="#f0f4f7").pack(pady=5)
    listbox = tk.Listbox(remove_win, width=80, font=("Consolas", 10))
    listbox.pack(padx=10, pady=10)
    student_map = {}
    
    for idx, s in enumerate(students):
        display = f"ID: {s['id']} | Name: {s['name']} | Program: {s['program']} | Expiry: {s['expiry']}"
        listbox.insert(tk.END, display)
        student_map[idx] = s['id']
    
    def remove_selected():
        selection = listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No student selected.")
            return
        idx = selection[0]
        student_id = student_map[idx]
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to remove student ID {student_id}?\n")
        if confirm:
            new_students = [s for s in students if s["id"] != student_id]
            save_students_list(new_students)
            log_admin_action(f"REMOVED STUDENT | ID: {student_id}")
            messagebox.showinfo("Removed", f"Student {student_id} removed.")
            remove_win.destroy()
            global last_scanned_student, current_student
            if last_scanned_student and last_scanned_student.get("id") == student_id:
                last_scanned_student = None
                current_student = None
                info_text.config(state="normal")
                info_text.delete(1.0, tk.END)
                info_text.config(state="disabled")
                verify_notify_label.config(text="")
                chat_button.config(state="disabled", bg="#cccccc")

    tk.Button(remove_win, text="Remove Selected", command=remove_selected, bg="#b71c1c", fg="white", font=("Arial", 10, "bold")).pack(pady=10)

# Global variables
last_scanned_student = None

# GUI setup
root = tk.Tk()
root.title("Student ID Scanner")
root.configure(bg="#e3eaf2")

header = tk.Label(root, text="Student ID Scanner System", font=("Arial", 16, "bold"), bg="#1976d2", fg="white", pady=10)
header.pack(fill="x")

tk.Label(root, text="Enter Student ID:", bg="#e3eaf2", font=("Arial", 11)).pack(pady=(15, 5))

# Limit entry_id to max 8 digits
def on_entry_id(*args):
    value = entry_id_var.get()
    if not value.isdigit():
        entry_id_var.set(''.join(filter(str.isdigit, value))[:8])
    elif len(value) > 8:
        entry_id_var.set(value[:8])

entry_id_var = tk.StringVar()
entry_id_var.trace_add("write", on_entry_id)

entry_id = tk.Entry(root, width=30, textvariable=entry_id_var, font=("Arial", 11))
entry_id.pack(pady=5)

btn_frame = tk.Frame(root, bg="#e3eaf2")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Scan", command=check_id, bg="#1976d2", fg="white", font=("Arial", 10, "bold"), width=12).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Verify", command=verify_student, bg="#ff9800", fg="white", font=("Arial", 10, "bold"), width=12).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Create Student", command=open_create_student, bg="#388e3c", fg="white", font=("Arial", 10, "bold"), width=12).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="List Students", command=list_students, bg="#0288d1", fg="white", font=("Arial", 10, "bold"), width=12).grid(row=0, column=3, padx=5)
tk.Button(btn_frame, text="Remove Student", command=open_remove_student_section, bg="#b71c1c", fg="white", font=("Arial", 10, "bold"), width=14).grid(row=0, column=4, padx=5)

# Add Chat button (initially disabled)
chat_button = tk.Button(btn_frame, text="💬 Student Chat", command=open_student_chat, bg="#cccccc", fg="white", font=("Arial", 10, "bold"), width=14, state="disabled")
chat_button.grid(row=1, column=0, columnspan=5, pady=(10, 0))

verify_notify_label = tk.Label(root, text="", bg="#e3eaf2", font=("Arial", 10, "bold"))
verify_notify_label.pack(pady=(0, 5))

info_text = tk.Text(root, width=40, height=10, font=("Consolas", 11), bg="#f5f5f5", fg="#222")
info_text.pack(pady=10)
info_text.config(state="disabled")

root.mainloop()
